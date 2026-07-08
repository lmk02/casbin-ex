defmodule Casbin.Runtime do
  @moduledoc """
  Lock-free enforcement against the `Casbin.Store` projection.

  `Casbin.EnforcerServer.allow?/2` used to round-trip the enforcer
  GenServer for every check, serializing all reads of a named enforcer
  through one process. This module evaluates the request in the calling
  process instead, and — when the matcher admits an index plan (see
  `Casbin.Model.MatcherAnalysis`) — probes only the policy buckets the
  request can possibly match:

    * `r.X == p.Y` conjuncts pin the bucket value exactly
    * `g(r.X, p.Y)` conjuncts expand to the roles reachable from `r.X`
      (memoized per role-graph version)

  Policies outside the plan live in a `:full` bucket that is always
  scanned, and the complete matcher still evaluates over every candidate,
  so pruning can never change a decision. Matchers without a plan (or
  role expansions above `@max_probes`) fall back to the chunked full scan
  with the same short-circuit semantics as `Casbin.Enforcer.allow?/2`.
  """

  alias Casbin.Internal.Digraph
  alias Casbin.Internal.PatternCache
  alias Casbin.Model
  alias Casbin.Model.MatcherAnalysis.Plan
  alias Casbin.Model.PolicyEffect
  alias Casbin.Model.Request
  alias Casbin.Store

  # Above this many candidate buckets a full scan is cheaper and simpler.
  @max_probes 512

  @doc """
  Evaluates `request` against the projected state of `ename`.

  Returns `{:ok, boolean}` or `:no_projection` when the enforcer has no
  store projection (callers fall back to the GenServer path).
  """
  @spec enforce(String.t(), [String.t()]) :: {:ok, boolean()} | :no_projection
  def enforce(ename, request) when is_list(request) do
    case Store.fetch_core(ename) do
      nil -> :no_projection
      core -> {:ok, do_enforce(ename, core, request)}
    end
  end

  defp do_enforce(ename, %{model: model} = core, request) do
    case Model.create_request(model, request) do
      {:error, _reason} ->
        Model.allow?(model, [])

      {:ok, req} ->
        decisive_allow? = PolicyEffect.mode(model.effect) == :allow_override
        found = decisive_match?(ename, core, req, decisive_allow?)
        if decisive_allow?, do: found, else: not found
    end
  end

  defp decisive_match?(ename, core, req, decisive_allow?) do
    case candidate_keys(ename, core, req) do
      :all ->
        full_scan(ename, core, req, decisive_allow?)

      keys ->
        probe_buckets(ename, core, req, decisive_allow?, keys)
    end
  end

  defp full_scan(ename, %{model: model, env: env, generation: generation}, req, decisive_allow?) do
    Store.reduce_policies(ename, generation, false, fn policies, acc ->
      if any_decisive?(policies, model, env, req, decisive_allow?) do
        {:halt, true}
      else
        {:cont, acc}
      end
    end)
  end

  defp probe_buckets(ename, core, req, decisive_allow?, keys) do
    %{model: model, env: env, generation: generation} = core

    Enum.any?([:full | keys], fn key ->
      ename
      |> Store.bucket_policies(generation, key)
      |> any_decisive?(model, env, req, decisive_allow?)
    end)
  end

  defp any_decisive?(policies, model, env, req, decisive_allow?) do
    Enum.any?(policies, fn policy ->
      Model.match?(model, req, policy, env) and
        Model.Policy.allow?(policy) == decisive_allow?
    end)
  end

  # Builds the list of index-key tuples this request can match, or :all
  # when the plan is absent/inapplicable or the expansion is too large.
  defp candidate_keys(_ename, %{plan: nil}, _req), do: :all

  defp candidate_keys(ename, %{plan: %Plan{} = plan} = core, %Request{attrs: attrs}) do
    values_per_position =
      Enum.map(plan.sources, fn
        {:eq, r_attr} ->
          case attrs[r_attr] do
            nil -> :unbound
            value -> [value]
          end

        {:g, gname, r_attr} ->
          case attrs[r_attr] do
            nil -> :unbound
            value -> role_candidates(ename, core, gname, value)
          end
      end)

    with false <- Enum.any?(values_per_position, &(&1 == :unbound)),
         product = Enum.reduce(values_per_position, 1, &(length(&1) * &2)),
         true <- product <= @max_probes do
      cartesian_keys(values_per_position)
    else
      _ -> :all
    end
  end

  defp candidate_keys(_ename, _core, _req), do: :all

  defp cartesian_keys(values_per_position) do
    values_per_position
    |> Enum.reverse()
    |> Enum.reduce([[]], fn values, acc ->
      for value <- values, rest <- acc, do: [value | rest]
    end)
    |> Enum.map(&List.to_tuple/1)
  end

  # The candidate policy-side values for g(r.X, p.Y): r.X itself plus all
  # roles reachable from it. Memoized per (graph version, value) — the
  # DFS runs once per role-graph mutation, not per request.
  defp role_candidates(ename, %{graph_versions: versions}, gname, value) do
    case versions[gname] do
      nil ->
        [value]

      version ->
        PatternCache.fetch(:role_names, {version, value}, fn ->
          build_role_candidates(ename, gname, version, value)
        end)
    end
  end

  defp role_candidates(_ename, _core, _gname, value), do: [value]

  defp build_role_candidates(ename, gname, version, value) do
    case Store.fetch_role_graph(ename, gname) do
      %Digraph{version: ^version} = graph -> reachable_names(graph, value)
      %Digraph{} = graph -> {:nocache, reachable_names(graph, value)}
      nil -> {:nocache, [value]}
    end
  end

  defp reachable_names(graph, value) do
    graph
    |> Digraph.reachable_vertices(value)
    |> Enum.filter(&is_binary/1)
    |> then(&Enum.uniq([value | &1]))
  end
end
