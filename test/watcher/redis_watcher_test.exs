defmodule Casbin.Watcher.RedisWatcherTest do
  # Exercises the RedisWatcher message handling deterministically by
  # injecting the messages Redix.PubSub would deliver. No Redis server is
  # required: Redix connections start lazily and simply keep retrying
  # against the unreachable port configured here.
  use ExUnit.Case, async: false

  alias Casbin.Watcher.Event
  alias Casbin.Watcher.RedisWatcher

  # nothing listens here; publishes fail (logged) and no real
  # subscription events interfere with the injected ones
  @dead_redis [host: "127.0.0.1", port: 1, sync_connect: false]

  setup context do
    name = :"redis_watcher_test_#{:erlang.phash2(context.test)}"

    {:ok, pid} =
      RedisWatcher.start_link(
        name: name,
        enforcer: "redis_test",
        redis: @dead_redis,
        reconcile_interval: nil
      )

    test_pid = self()
    :ok = RedisWatcher.set_update_callback(name, fn event -> send(test_pid, {:event, event}) end)

    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    %{name: name, pid: pid}
  end

  defp subscribed(pid), do: send(pid, {:redix_pubsub, self(), make_ref(), :subscribed, %{}})

  defp message(pid, payload),
    do: send(pid, {:redix_pubsub, self(), make_ref(), :message, %{payload: payload}})

  test "first subscription does not trigger a reload", %{pid: pid} do
    subscribed(pid)
    refute_receive {:event, _}, 50
  end

  test "re-subscription after a disconnect triggers a full reload", %{pid: pid} do
    subscribed(pid)
    send(pid, {:redix_pubsub, self(), make_ref(), :disconnected, %{error: :closed}})
    subscribed(pid)

    assert_receive {:event, %Event{op: :full_reload}}
  end

  test "peer messages are decoded and delivered", %{pid: pid} do
    payload =
      Event.encode!(%Event{
        op: :add_policy,
        ptype: :p,
        rules: [["alice", "data1", "read"]],
        instance_id: "peer"
      })

    message(pid, payload)

    assert_receive {:event, %Event{op: :add_policy, rules: [["alice", "data1", "read"]]}}
  end

  test "own messages echoed back are dropped", %{name: name, pid: pid} do
    own_id = RedisWatcher.instance_id(name)
    payload = Event.encode!(%Event{op: :add_policy, ptype: :p, instance_id: own_id})

    message(pid, payload)
    refute_receive {:event, _}, 50
  end

  test "malformed payloads are dropped without crashing", %{name: name, pid: pid} do
    message(pid, "{not json")
    message(pid, ~s({"op":"drop_table"}))
    refute_receive {:event, _}, 50
    assert Process.alive?(pid)

    # still functional afterwards
    message(pid, Event.encode!(%Event{op: :full_reload, instance_id: "peer"}))
    assert_receive {:event, %Event{op: :full_reload}}
    assert RedisWatcher.instance_id(name)
  end

  test "a failing callback does not crash the watcher", %{name: name, pid: pid} do
    :ok = RedisWatcher.set_update_callback(name, fn _ -> raise "boom" end)
    message(pid, Event.encode!(%Event{op: :full_reload, instance_id: "peer"}))

    # process survives and can still answer calls
    assert RedisWatcher.instance_id(name)
  end

  test "await_ready blocks until subscribed", %{name: name, pid: pid} do
    task = Task.async(fn -> RedisWatcher.await_ready(name, 1_000) end)
    refute Task.yield(task, 50)

    subscribed(pid)
    assert Task.await(task) == :ok

    # immediate once ready
    assert RedisWatcher.await_ready(name, 100) == :ok
  end
end
