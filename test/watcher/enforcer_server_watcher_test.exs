defmodule Casbin.EnforcerServerWatcherTest do
  use ExUnit.Case, async: false

  alias Casbin.EnforcerServer
  alias Casbin.EnforcerSupervisor
  alias Casbin.Persist.ReadonlyFileAdapter
  alias Casbin.TestWatcher
  alias Casbin.Watcher.Event

  @rbac_conf "../data/rbac.conf" |> Path.expand(__DIR__)
  @rbac_csv "../data/rbac.csv" |> Path.expand(__DIR__)

  setup context do
    ename = "watcher_test_#{context.test |> :erlang.phash2()}"
    watcher_name = :"#{ename}_watcher"

    {:ok, _} = TestWatcher.start_link(test_pid: self(), name: watcher_name)
    {:ok, pid} = EnforcerSupervisor.start_enforcer(ename, @rbac_conf)

    :ok = EnforcerServer.set_watcher(ename, {TestWatcher, watcher_name})

    on_exit(fn ->
      if Process.alive?(pid),
        do: DynamicSupervisor.terminate_child(Casbin.EnforcerSupervisor, pid)

      :ets.delete(:enforcers_table, ename)
    end)

    %{ename: ename, watcher: watcher_name}
  end

  test "mutations publish events stamped with the watcher instance id", %{
    ename: ename,
    watcher: watcher
  } do
    :ok = EnforcerServer.add_policy(ename, {:p, ["alice", "blog_post", "read"]})

    own_id = TestWatcher.instance_id(watcher)

    assert_receive {:notified,
                    %Event{
                      op: :add_policy,
                      ptype: :p,
                      rules: [["alice", "blog_post", "read"]],
                      instance_id: ^own_id,
                      enforcer: ^ename
                    }}

    :ok = EnforcerServer.add_mapping_policy(ename, {:g, "bob", "admin"})

    assert_receive {:notified,
                    %Event{op: :add_mapping_policy, ptype: :g, rules: [["bob", "admin"]]}}

    :ok = EnforcerServer.remove_policy(ename, {:p, ["alice", "blog_post", "read"]})
    assert_receive {:notified, %Event{op: :remove_policy}}

    :ok = EnforcerServer.remove_mapping_policy(ename, {:g, "bob", "admin"})
    assert_receive {:notified, %Event{op: :remove_mapping_policy}}
  end

  test "failed mutations publish nothing", %{ename: ename} do
    {:error, :nonexistent} = EnforcerServer.remove_policy(ename, {:p, ["ghost", "x", "y"]})
    refute_receive {:notified, _}, 50
  end

  test "peer events apply incrementally without republishing", %{
    ename: ename,
    watcher: watcher
  } do
    event = %Event{
      op: :add_policy,
      ptype: :p,
      rules: [["alice", "blog_post", "read"]],
      instance_id: "peer"
    }

    assert :ok = TestWatcher.deliver(watcher, event)
    assert EnforcerServer.allow?(ename, ["alice", "blog_post", "read"])

    # applying a replicated change must not publish a new event (loop!)
    refute_receive {:notified, _}, 50

    # idempotent redelivery
    assert :ok = TestWatcher.deliver(watcher, event)
    assert EnforcerServer.allow?(ename, ["alice", "blog_post", "read"])

    remove = %{event | op: :remove_policy}
    assert :ok = TestWatcher.deliver(watcher, remove)
    refute EnforcerServer.allow?(ename, ["alice", "blog_post", "read"])
  end

  test "peer mapping events update the role graph", %{ename: ename, watcher: watcher} do
    :ok =
      TestWatcher.deliver(watcher, %Event{
        op: :add_policy,
        ptype: :p,
        rules: [["admin", "blog_post", "delete"]],
        instance_id: "peer"
      })

    :ok =
      TestWatcher.deliver(watcher, %Event{
        op: :add_mapping_policy,
        ptype: :g,
        rules: [["alice", "admin"]],
        instance_id: "peer"
      })

    assert EnforcerServer.allow?(ename, ["alice", "blog_post", "delete"])

    :ok =
      TestWatcher.deliver(watcher, %Event{
        op: :remove_mapping_policy,
        ptype: :g,
        rules: [["alice", "admin"]],
        instance_id: "peer"
      })

    refute EnforcerServer.allow?(ename, ["alice", "blog_post", "delete"])
  end

  test "own events echoed back are dropped", %{ename: ename, watcher: watcher} do
    own_id = TestWatcher.instance_id(watcher)

    event = %Event{
      op: :add_policy,
      ptype: :p,
      rules: [["alice", "blog_post", "read"]],
      instance_id: own_id
    }

    assert :ok = TestWatcher.deliver(watcher, event)
    refute EnforcerServer.allow?(ename, ["alice", "blog_post", "read"])
  end

  test "stale and duplicate revisions are dropped", %{ename: ename, watcher: watcher} do
    add = fn rule, rev ->
      %Event{op: :add_policy, ptype: :p, rules: [rule], instance_id: "peer", revision: rev}
    end

    :ok = TestWatcher.deliver(watcher, add.(["alice", "blog_post", "read"], 5))
    assert EnforcerServer.get_revision(ename) == 5

    # same revision again: dropped
    :ok = TestWatcher.deliver(watcher, add.(["alice", "comment", "read"], 5))
    refute EnforcerServer.allow?(ename, ["alice", "comment", "read"])

    # next revision: applied
    :ok = TestWatcher.deliver(watcher, add.(["alice", "comment", "read"], 6))
    assert EnforcerServer.allow?(ename, ["alice", "comment", "read"])
    assert EnforcerServer.get_revision(ename) == 6
  end

  test "revision gaps trigger a reload from storage", %{ename: ename, watcher: watcher} do
    :ok = EnforcerServer.set_persist_adapter(ename, ReadonlyFileAdapter.new(@rbac_csv))
    :ok = EnforcerServer.load_policies(ename)
    :ok = EnforcerServer.load_mapping_policies(ename)

    add = fn rule, rev ->
      %Event{op: :add_policy, ptype: :p, rules: [rule], instance_id: "peer", revision: rev}
    end

    :ok = TestWatcher.deliver(watcher, add.(["mallory", "blog_post", "delete"], 1))
    assert EnforcerServer.allow?(ename, ["mallory", "blog_post", "delete"])

    # revision jumps from 1 to 3: something was missed, reload from the
    # adapter discards the drifted rule and the gap event's payload alike
    :ok = TestWatcher.deliver(watcher, add.(["eve", "blog_post", "delete"], 3))

    refute EnforcerServer.allow?(ename, ["mallory", "blog_post", "delete"])
    refute EnforcerServer.allow?(ename, ["eve", "blog_post", "delete"])
    assert EnforcerServer.allow?(ename, ["bob", "blog_post", "read"])
    assert EnforcerServer.get_revision(ename) == 3
  end

  test "full_reload events resynchronize from storage", %{ename: ename, watcher: watcher} do
    :ok = EnforcerServer.set_persist_adapter(ename, ReadonlyFileAdapter.new(@rbac_csv))
    :ok = EnforcerServer.load_policies(ename)
    :ok = EnforcerServer.load_mapping_policies(ename)

    :ok =
      TestWatcher.deliver(watcher, %Event{
        op: :add_policy,
        ptype: :p,
        rules: [["mallory", "blog_post", "delete"]],
        instance_id: "peer"
      })

    assert EnforcerServer.allow?(ename, ["mallory", "blog_post", "delete"])

    :ok = TestWatcher.deliver(watcher, %Event{op: :full_reload, instance_id: "peer"})

    refute EnforcerServer.allow?(ename, ["mallory", "blog_post", "delete"])
    assert EnforcerServer.allow?(ename, ["bob", "blog_post", "read"])
  end
end
