defmodule Casbin.Store do
  @moduledoc """
  Shared-ETS projection of enforcer state for the lock-free read path.

  `Casbin.EnforcerServer` remains the single writer; every mutation is
  projected here before the server replies (read-your-writes). Readers
  (`Casbin.Runtime`) evaluate requests directly against these tables in
  their own process, so enforcement no longer serializes through the
  enforcer GenServer.

  Tables:

    * `:casbin_cores` — one small row per enforcer: model (with the
      compiled matcher), the matcher env, and the current policy
      generation. Copied per read, so it must stay small — role graphs
      live in their own table and the env holds ETS-backed role stubs.
    * `:casbin_policies` — `ordered_set`; key
      `{ename, generation, index_key, hash}` so a bound prefix is an
      efficient range scan. `index_key` is the policy's value tuple under
      the enforcer's index plan (see `Casbin.Model.MatcherAnalysis`), or
      `:full` for policies outside the plan.
    * `:casbin_role_graphs` — `{{ename, gname}, digraph}`; only read on a
      reachability-cache miss, never on the per-request hot path.

  Consistency: single-row changes (add/remove policy) mutate the current
  generation in place — each is atomic. Bulk changes (loads, reloads,
  filtered removes, mapping updates that rebuild the env) write a fresh
  generation and atomically swap the core row; readers holding the old
  core keep scanning the old generation's rows, which are only deleted
  two generations later.
  """

  alias Casbin.Enforcer
  alias Casbin.Internal.RoleGroup
  alias Casbin.Model
  alias Casbin.Model.MatcherAnalysis

  @cores :casbin_cores
  @policies :casbin_policies
  @role_graphs :casbin_role_graphs

  @doc false
  def ensure_tables do
    if :ets.whereis(@cores) == :undefined do
      :ets.new(@cores, [:set, :public, :named_table, read_concurrency: true])
    end

    if :ets.whereis(@policies) == :undefined do
      :ets.new(@policies, [
        :ordered_set,
        :public,
        :named_table,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    if :ets.whereis(@role_graphs) == :undefined do
      :ets.new(@role_graphs, [:set, :public, :named_table, read_concurrency: true])
    end

    :ok
  end

  @doc """
  Returns the core row for `ename`, or `nil` when the enforcer has no
  projection (not started through `Casbin.EnforcerServer`).
  """
  def fetch_core(ename) do
    case :ets.lookup(@cores, ename) do
      [{^ename, core}] -> core
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  end

  @doc """
  Folds over the policy rows of `generation` in chunks, stopping early
  when `fun` returns `{:halt, acc}`.
  """
  def reduce_policies(ename, generation, acc, fun) do
    match_spec = [{{{ename, generation, :_, :_}, :"$1"}, [], [:"$1"]}]
    reduce_chunks(:ets.select(@policies, match_spec, 200), acc, fun)
  rescue
    ArgumentError -> acc
  end

  @doc """
  Returns the policies stored under exactly `index_key` (a value tuple or
  the `:full` sentinel) for `generation`.
  """
  def bucket_policies(ename, generation, index_key) do
    :ets.select(@policies, [{{{ename, generation, index_key, :_}, :"$1"}, [], [:"$1"]}])
  rescue
    ArgumentError -> []
  end

  defp reduce_chunks(:"$end_of_table", acc, _fun), do: acc

  defp reduce_chunks({policies, continuation}, acc, fun) do
    case fun.(policies, acc) do
      {:halt, acc} -> acc
      {:cont, acc} -> reduce_chunks(:ets.select(continuation), acc, fun)
    end
  end

  @doc """
  Returns the role graph projected for `{ename, gname}`, or `nil`.
  """
  def fetch_role_graph(ename, gname) do
    case :ets.lookup(@role_graphs, {ename, gname}) do
      [{_key, graph}] -> graph
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  end

  @doc """
  Projects `enforcer` for `ename`. `change` hints how to update the
  policy rows:

    * `{:add, [{key, attrs}]}` / `{:remove, [{key, attrs}]}` — atomic
      single-row updates within the current generation
    * `:bulk` — rewrite everything under a fresh generation

  Called only from the owning `EnforcerServer` process (single writer).
  """
  def sync(ename, %Enforcer{} = enforcer, change) do
    generation = current_generation(ename)
    do_sync(ename, enforcer, change, generation)
    :ok
  rescue
    # Tables unavailable (application not started): reads fall back to the
    # GenServer path, so skipping the projection is safe.
    ArgumentError -> :ok
  end

  @doc """
  Removes every projection row for `ename`.
  """
  def drop(ename) do
    :ets.delete(@cores, ename)
    :ets.match_delete(@policies, {{ename, :_, :_, :_}, :_})
    :ets.match_delete(@role_graphs, {{ename, :_}, :_})
    :ok
  rescue
    ArgumentError -> :ok
  end

  #
  # Internals
  #

  defp current_generation(ename) do
    case fetch_core(ename) do
      %{generation: generation} -> generation
      nil -> 0
    end
  end

  defp do_sync(ename, enforcer, {:add, rules}, generation) when generation > 0 do
    plan = plan_for(enforcer.model)

    Enum.each(rules, fn rule ->
      case Model.create_policy(enforcer.model, rule) do
        {:ok, policy} ->
          :ets.insert(@policies, {row_key(ename, generation, plan, policy), policy})

        {:error, _reason} ->
          :ok
      end
    end)

    put_core(ename, enforcer, generation)
  end

  defp do_sync(ename, enforcer, {:remove, rules}, generation) when generation > 0 do
    plan = plan_for(enforcer.model)

    Enum.each(rules, fn rule ->
      case Model.create_policy(enforcer.model, rule) do
        {:ok, policy} ->
          :ets.delete(@policies, row_key(ename, generation, plan, policy))

        {:error, _reason} ->
          :ok
      end
    end)

    put_core(ename, enforcer, generation)
  end

  defp do_sync(ename, enforcer, :roles, generation) when generation > 0 do
    project_role_graphs(ename, enforcer)
    put_core(ename, enforcer, generation)
  end

  defp do_sync(ename, enforcer, :none, generation) when generation > 0 do
    put_core(ename, enforcer, generation)
  end

  defp do_sync(ename, enforcer, _bulk_or_uninitialized, generation) do
    next = generation + 1
    plan = plan_for(enforcer.model)

    Enum.each(enforcer.policies, fn policy ->
      :ets.insert(@policies, {row_key(ename, next, plan, policy), policy})
    end)

    project_role_graphs(ename, enforcer)

    # Atomic swap: readers pick up the new generation with this insert.
    put_core(ename, enforcer, next)

    # Delete two generations back; readers still scanning generation
    # `generation` (fetched their core just before the swap) are unaffected.
    if generation > 0 do
      :ets.match_delete(@policies, {{ename, generation - 1, :_, :_}, :_})
    end
  end

  defp row_key(ename, generation, plan, policy) do
    {ename, generation, MatcherAnalysis.index_key(plan, policy), :erlang.phash2(policy)}
  end

  defp plan_for(%Model{matcher: %{ast: ast}, role_mappings: role_mappings}),
    do: MatcherAnalysis.analyze(ast, role_mappings)

  defp plan_for(_model), do: nil

  defp project_role_graphs(ename, %Enforcer{role_groups: role_groups}) do
    Enum.each(role_groups, fn {gname, group} ->
      :ets.insert(@role_graphs, {{ename, gname}, group.role_graph})
    end)
  end

  defp put_core(ename, %Enforcer{model: model, env: env, role_groups: role_groups}, generation) do
    graph_versions =
      Map.new(role_groups, fn {gname, group} -> {gname, group.role_graph.version} end)

    core = %{
      model: model,
      env: runtime_env(ename, env, role_groups),
      generation: generation,
      plan: plan_for(model),
      graph_versions: graph_versions
    }

    :ets.insert(@cores, {ename, core})
  end

  # The struct env holds role stubs that capture the full role graph —
  # copying them out of ETS on every read would defeat the purpose. The
  # projected env replaces them with stubs that resolve through the
  # reachability cache and only load the graph from ETS on a miss.
  defp runtime_env(ename, env, role_groups) do
    Enum.reduce(role_groups, env, fn {gname, group}, acc ->
      version = group.role_graph.version

      case Map.fetch(acc, gname) do
        {:ok, fun} when is_function(fun, 2) ->
          Map.put(acc, gname, RoleGroup.ets_stub_2(ename, gname, version))

        {:ok, fun} when is_function(fun, 3) ->
          Map.put(acc, gname, RoleGroup.ets_stub_3(ename, gname, version))

        _ ->
          acc
      end
    end)
  end
end
