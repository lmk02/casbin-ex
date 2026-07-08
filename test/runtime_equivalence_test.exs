defmodule Casbin.RuntimeEquivalenceTest do
  # Differential test: the lock-free ETS read path (Casbin.Runtime via
  # EnforcerServer.allow?) must decide exactly like the naive struct path
  # (Enforcer.allow?) for the same policy set — the struct path is the
  # oracle.
  use ExUnit.Case, async: false

  alias Casbin.Enforcer
  alias Casbin.EnforcerServer
  alias Casbin.EnforcerSupervisor

  @seed 421
  @subjects ~w(alice bob carol dave eve)
  @objects ~w(blog_post comment profile settings report)
  @actions ~w(read write delete modify)
  @roles ~w(reader author admin auditor)

  defp start(ename, conf) do
    {:ok, pid} = EnforcerSupervisor.start_enforcer(ename, Path.expand("data/#{conf}", __DIR__))

    on_exit(fn ->
      if Process.alive?(pid),
        do: DynamicSupervisor.terminate_child(Casbin.EnforcerSupervisor, pid)

      :ets.delete(:enforcers_table, ename)
    end)

    pid
  end

  defp random_scenarios(rand_state, count, generator) do
    Enum.map_reduce(1..count, rand_state, fn _, state -> generator.(state) end)
  end

  defp pick(list, state) do
    {idx, state} = :rand.uniform_s(length(list), state)
    {Enum.at(list, idx - 1), state}
  end

  test "ACL with random policies, denies and removals" do
    ename = "diff_acl"
    start(ename, "acl.conf")
    {:ok, oracle} = Enforcer.init(Path.expand("data/acl.conf", __DIR__))

    state = :rand.seed_s(:exsss, @seed)

    {rules, state} =
      random_scenarios(state, 60, fn s ->
        {sub, s} = pick(@subjects, s)
        {obj, s} = pick(@objects, s)
        {act, s} = pick(@actions, s)
        {eft_roll, s} = :rand.uniform_s(5, s)
        attrs = if eft_roll == 1, do: [sub, obj, act, "deny"], else: [sub, obj, act]
        {attrs, s}
      end)

    oracle =
      Enum.reduce(Enum.uniq(rules), oracle, fn attrs, e ->
        :ok = EnforcerServer.add_policy(ename, {:p, attrs})
        Enforcer.add_policy!(e, {:p, attrs})
      end)

    # remove a few again
    to_remove = rules |> Enum.uniq() |> Enum.take_every(7)

    oracle =
      Enum.reduce(to_remove, oracle, fn attrs, e ->
        :ok = EnforcerServer.remove_policy(ename, {:p, attrs})
        Enforcer.remove_policy!(e, {:p, attrs})
      end)

    {_, _} =
      random_scenarios(state, 300, fn s ->
        {sub, s} = pick(@subjects ++ ["mallory"], s)
        {obj, s} = pick(@objects ++ ["unknown"], s)
        {act, s} = pick(@actions, s)
        req = [sub, obj, act]

        assert EnforcerServer.allow?(ename, req) == Enforcer.allow?(oracle, req),
               "divergence for #{inspect(req)}"

        {req, s}
      end)
  end

  test "RBAC with random role chains" do
    ename = "diff_rbac"
    start(ename, "rbac.conf")
    {:ok, oracle} = Enforcer.init(Path.expand("data/rbac.conf", __DIR__))

    state = :rand.seed_s(:exsss, @seed + 1)

    {perm_rules, state} =
      random_scenarios(state, 30, fn s ->
        {role, s} = pick(@roles, s)
        {obj, s} = pick(@objects, s)
        {act, s} = pick(@actions, s)
        {[role, obj, act], s}
      end)

    {mappings, state} =
      random_scenarios(state, 20, fn s ->
        {sub, s} = pick(@subjects, s)
        {role, s} = pick(@roles, s)
        {parent, s} = pick(@roles, s)
        {mix, s} = :rand.uniform_s(2, s)
        mapping = if mix == 1, do: {:g, sub, role}, else: {:g, role, parent}
        {mapping, s}
      end)

    oracle =
      Enum.reduce(Enum.uniq(perm_rules), oracle, fn attrs, e ->
        :ok = EnforcerServer.add_policy(ename, {:p, attrs})
        Enforcer.add_policy!(e, {:p, attrs})
      end)

    oracle =
      Enum.reduce(Enum.uniq(mappings), oracle, fn {:g, r1, r2} = mapping, e ->
        case EnforcerServer.add_mapping_policy(ename, mapping) do
          :ok ->
            case Enforcer.add_mapping_policy(e, {:g, r1, r2}) do
              {:error, _} -> e
              new_e -> new_e
            end

          {:error, _} ->
            e
        end
      end)

    {_, _} =
      random_scenarios(state, 300, fn s ->
        {sub, s} = pick(@subjects ++ @roles, s)
        {obj, s} = pick(@objects, s)
        {act, s} = pick(@actions, s)
        req = [sub, obj, act]

        assert EnforcerServer.allow?(ename, req) == Enforcer.allow?(oracle, req),
               "divergence for #{inspect(req)}"

        {req, s}
      end)
  end

  test "keyMatch2 pattern policies" do
    ename = "diff_km2"
    start(ename, "keymatch2.conf")
    {:ok, oracle} = Enforcer.init(Path.expand("data/keymatch2.conf", __DIR__))

    rules = [
      ["alice", "/res/:id", "GET"],
      ["alice", "/res/:id/sub/*", "POST"],
      ["bob", "/admin/*", "GET"],
      ["carol", "/files/:name", "DELETE"]
    ]

    oracle =
      Enum.reduce(rules, oracle, fn attrs, e ->
        :ok = EnforcerServer.add_policy(ename, {:p, attrs})
        Enforcer.add_policy!(e, {:p, attrs})
      end)

    requests = [
      ["alice", "/res/42", "GET"],
      ["alice", "/res/42/sub/x/y", "POST"],
      ["alice", "/admin/x", "GET"],
      ["bob", "/admin/anything", "GET"],
      ["bob", "/res/42", "GET"],
      ["carol", "/files/report.pdf", "DELETE"],
      ["carol", "/files/a/b", "DELETE"],
      ["mallory", "/res/42", "GET"]
    ]

    for req <- requests do
      assert EnforcerServer.allow?(ename, req) == Enforcer.allow?(oracle, req),
             "divergence for #{inspect(req)}"
    end
  end
end
