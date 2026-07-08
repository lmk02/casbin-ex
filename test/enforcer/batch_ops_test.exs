defmodule Casbin.Enforcer.BatchOpsTest do
  use ExUnit.Case, async: false

  alias Casbin.Enforcer
  alias Casbin.EnforcerServer
  alias Casbin.EnforcerSupervisor
  alias Casbin.TestWatcher
  alias Casbin.Watcher.Event

  @acl_conf "../data/acl.conf" |> Path.expand(__DIR__)

  describe "Enforcer.add_policies/2 and remove_policies/2" do
    test "adds and removes batches, skipping duplicates and absentees" do
      {:ok, e} = Enforcer.init(@acl_conf)

      rules = [
        {:p, ["alice", "blog_post", "read"]},
        {:p, ["bob", "blog_post", "read"]},
        # duplicate inside the batch
        {:p, ["alice", "blog_post", "read"]}
      ]

      e = Enforcer.add_policies(e, rules)
      assert length(Enforcer.list_policies(e)) == 2
      assert Enforcer.allow?(e, ["alice", "blog_post", "read"])

      # re-adding the same batch is a no-op
      e = Enforcer.add_policies(e, rules)
      assert length(Enforcer.list_policies(e)) == 2

      e =
        Enforcer.remove_policies(e, [
          {:p, ["alice", "blog_post", "read"]},
          # not present: ignored
          {:p, ["ghost", "x", "y"]}
        ])

      refute Enforcer.allow?(e, ["alice", "blog_post", "read"])
      assert Enforcer.allow?(e, ["bob", "blog_post", "read"])
    end

    test "an invalid rule fails the whole batch" do
      {:ok, e} = Enforcer.init(@acl_conf)

      assert {:error, _} =
               Enforcer.add_policies(e, [
                 {:p, ["alice", "blog_post", "read"]},
                 {:nope, ["x"]}
               ])
    end
  end

  describe "EnforcerServer batch API" do
    setup do
      ename = "batch_test_#{System.unique_integer([:positive])}"
      watcher = :"#{ename}_watcher"
      {:ok, _} = TestWatcher.start_link(test_pid: self(), name: watcher)
      {:ok, pid} = EnforcerSupervisor.start_enforcer(ename, @acl_conf)
      :ok = EnforcerServer.set_watcher(ename, {TestWatcher, watcher})

      on_exit(fn ->
        if Process.alive?(pid),
          do: DynamicSupervisor.terminate_child(Casbin.EnforcerSupervisor, pid)

        :ets.delete(:enforcers_table, ename)
      end)

      %{ename: ename}
    end

    test "batch add/remove emit one event each and enforce correctly", %{ename: ename} do
      attrs = [["alice", "blog_post", "read"], ["bob", "blog_post", "write"]]

      :ok = EnforcerServer.add_policies(ename, :p, attrs)
      assert_receive {:notified, %Event{op: :add_policy, ptype: :p, rules: ^attrs}}
      refute_receive {:notified, _}, 20

      assert EnforcerServer.allow?(ename, ["alice", "blog_post", "read"])
      assert EnforcerServer.allow?(ename, ["bob", "blog_post", "write"])

      :ok = EnforcerServer.remove_policies(ename, :p, attrs)
      assert_receive {:notified, %Event{op: :remove_policy, ptype: :p, rules: ^attrs}}

      refute EnforcerServer.allow?(ename, ["alice", "blog_post", "read"])
      refute EnforcerServer.allow?(ename, ["bob", "blog_post", "write"])
    end
  end
end
