defmodule Casbin.Enforcer.ReplicationTest do
  # Covers the memory-only apply_* functions and reload_policies!/1 that
  # back the watcher (multi-instance sync) integration.
  use ExUnit.Case, async: true

  alias Casbin.Enforcer
  alias Casbin.Persist.ReadonlyFileAdapter

  @rbac_conf "../data/rbac.conf" |> Path.expand(__DIR__)
  @rbac_csv "../data/rbac.csv" |> Path.expand(__DIR__)

  defp rbac_enforcer do
    {:ok, e} = Enforcer.init(@rbac_conf)
    e
  end

  describe "apply_added_policy/2" do
    test "adds to memory and is idempotent" do
      e = rbac_enforcer()
      rule = {:p, ["alice", "blog_post", "read"]}

      e = Enforcer.apply_added_policy(e, rule)
      assert Enforcer.allow?(e, ["alice", "blog_post", "read"])

      # applying the same rule again is a no-op, not an error
      e2 = Enforcer.apply_added_policy(e, rule)
      assert e2 == e
    end

    test "ignores malformed rules" do
      e = rbac_enforcer()
      assert Enforcer.apply_added_policy(e, {:nonexistent_key, ["a", "b", "c"]}) == e
    end
  end

  describe "apply_removed_policy/2" do
    test "removes from memory and is idempotent" do
      e = rbac_enforcer()
      rule = {:p, ["alice", "blog_post", "read"]}

      e = Enforcer.apply_added_policy(e, rule)
      e = Enforcer.apply_removed_policy(e, rule)
      refute Enforcer.allow?(e, ["alice", "blog_post", "read"])

      assert Enforcer.apply_removed_policy(e, rule) == e
    end
  end

  describe "apply_removed_filtered_policy/4" do
    test "removes matching policies from memory only" do
      e =
        rbac_enforcer()
        |> Enforcer.apply_added_policy({:p, ["alice", "blog_post", "read"]})
        |> Enforcer.apply_added_policy({:p, ["alice", "comment", "read"]})
        |> Enforcer.apply_added_policy({:p, ["bob", "comment", "read"]})

      e = Enforcer.apply_removed_filtered_policy(e, :p, 0, ["alice"])

      refute Enforcer.allow?(e, ["alice", "blog_post", "read"])
      assert Enforcer.allow?(e, ["bob", "comment", "read"])

      # the removed rules can be re-added (set bookkeeping stays in sync)
      e = Enforcer.apply_added_policy(e, {:p, ["alice", "comment", "read"]})
      assert Enforcer.allow?(e, ["alice", "comment", "read"])
    end
  end

  describe "apply mapping policies" do
    test "add and remove update the role graph, idempotently" do
      e =
        rbac_enforcer()
        |> Enforcer.apply_added_policy({:p, ["admin", "blog_post", "delete"]})
        |> Enforcer.apply_added_mapping_policy({:g, "alice", "admin"})

      assert Enforcer.allow?(e, ["alice", "blog_post", "delete"])

      assert Enforcer.apply_added_mapping_policy(e, {:g, "alice", "admin"}) == e
      assert Enforcer.apply_added_mapping_policy(e, {:g2, "x", "y"}) == e

      e = Enforcer.apply_removed_mapping_policy(e, {:g, "alice", "admin"})
      refute Enforcer.allow?(e, ["alice", "blog_post", "delete"])

      assert Enforcer.apply_removed_mapping_policy(e, {:g, "alice", "admin"}) == e
    end
  end

  describe "reload_policies!/1" do
    test "discards drifted memory state and reloads from the adapter" do
      {:ok, e} = Enforcer.init(@rbac_conf)

      e =
        e
        |> Enforcer.set_persist_adapter(ReadonlyFileAdapter.new(@rbac_csv))
        |> Enforcer.load_policies!()
        |> Enforcer.load_mapping_policies!()

      assert Enforcer.allow?(e, ["bob", "blog_post", "read"])

      # drift memory away from storage (adapter writes are no-ops here)
      drifted =
        e
        |> Enforcer.apply_removed_mapping_policy({:g, "bob", "reader"})
        |> Enforcer.apply_added_policy({:p, ["mallory", "blog_post", "delete"]})

      refute Enforcer.allow?(drifted, ["bob", "blog_post", "read"])
      assert Enforcer.allow?(drifted, ["mallory", "blog_post", "delete"])

      reloaded = Enforcer.reload_policies!(drifted)

      assert Enforcer.allow?(reloaded, ["bob", "blog_post", "read"])
      refute Enforcer.allow?(reloaded, ["mallory", "blog_post", "delete"])

      # same policy state as a fresh load
      assert Enum.sort(Enforcer.list_policies(reloaded)) == Enum.sort(Enforcer.list_policies(e))

      assert Enum.sort(Enforcer.list_mapping_policies(reloaded)) ==
               Enum.sort(Enforcer.list_mapping_policies(e))
    end

    test "preserves user-defined env functions" do
      {:ok, e} = Enforcer.init(@rbac_conf)

      e =
        e
        |> Enforcer.set_persist_adapter(ReadonlyFileAdapter.new(@rbac_csv))
        |> Enforcer.load_policies!()
        |> Enforcer.load_mapping_policies!()
        |> Enforcer.add_fun({:my_fun, fn x, y -> x + y end})

      reloaded = Enforcer.reload_policies!(e)

      assert %Enforcer{env: %{my_fun: f}, persist_adapter: %ReadonlyFileAdapter{}} = reloaded
      assert f.(1, 2) == 3
    end
  end
end
