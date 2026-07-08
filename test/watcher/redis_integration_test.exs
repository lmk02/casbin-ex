defmodule Casbin.Watcher.RedisIntegrationTest do
  @moduledoc """
  End-to-end sync through a real Redis: two enforcers (simulating two
  service instances) share one pub/sub channel; a mutation on one becomes
  enforceable on the other.

  Requires Redis (see test/docker/docker-compose.yml):

      docker compose -f test/docker/docker-compose.yml up -d redis
      mix test --include redis
  """
  use ExUnit.Case, async: false

  @moduletag :redis

  alias Casbin.EnforcerServer
  alias Casbin.EnforcerSupervisor
  alias Casbin.Watcher.RedisWatcher

  @rbac_conf "../data/rbac.conf" |> Path.expand(__DIR__)
  @redis [
    host: System.get_env("REDIS_HOST", "127.0.0.1"),
    port: String.to_integer(System.get_env("REDIS_PORT", "6379"))
  ]

  defp eventually(fun, attempts \\ 50) do
    if fun.() do
      :ok
    else
      if attempts == 0, do: flunk("condition not met in time")
      Process.sleep(20)
      eventually(fun, attempts - 1)
    end
  end

  setup context do
    channel = "casbin:test:#{:erlang.phash2(context.test)}:#{System.unique_integer([:positive])}"

    instances =
      for suffix <- ["a", "b"] do
        ename = "redis_int_#{:erlang.phash2(context.test)}_#{suffix}"
        watcher = :"#{ename}_watcher"

        {:ok, wpid} =
          RedisWatcher.start_link(
            name: watcher,
            enforcer: ename,
            redis: @redis,
            channel: channel,
            reconcile_interval: nil
          )

        {:ok, epid} =
          EnforcerSupervisor.start_enforcer(ename, @rbac_conf,
            watcher: {RedisWatcher, watcher},
            load: false
          )

        on_exit(fn ->
          if Process.alive?(epid),
            do: DynamicSupervisor.terminate_child(Casbin.EnforcerSupervisor, epid)

          if Process.alive?(wpid), do: GenServer.stop(wpid)
          :ets.delete(:enforcers_table, ename)
        end)

        ename
      end

    [a, b] = instances
    %{a: a, b: b}
  end

  test "a policy added on instance A becomes enforceable on instance B", %{a: a, b: b} do
    refute EnforcerServer.allow?(b, ["alice", "blog_post", "read"])

    :ok = EnforcerServer.add_policy(a, {:p, ["alice", "blog_post", "read"]})

    eventually(fn -> EnforcerServer.allow?(b, ["alice", "blog_post", "read"]) end)

    # the originator did not reprocess its own event: still exactly one rule
    assert length(EnforcerServer.list_policies(a, %{})) == 1
    assert length(EnforcerServer.list_policies(b, %{})) == 1
  end

  test "removals and role mappings propagate", %{a: a, b: b} do
    :ok = EnforcerServer.add_policy(a, {:p, ["admin", "blog_post", "delete"]})
    :ok = EnforcerServer.add_mapping_policy(a, {:g, "alice", "admin"})

    eventually(fn -> EnforcerServer.allow?(b, ["alice", "blog_post", "delete"]) end)

    :ok = EnforcerServer.remove_mapping_policy(a, {:g, "alice", "admin"})
    eventually(fn -> not EnforcerServer.allow?(b, ["alice", "blog_post", "delete"]) end)

    :ok = EnforcerServer.remove_policy(a, {:p, ["admin", "blog_post", "delete"]})
    eventually(fn -> not EnforcerServer.allow?(b, ["admin", "blog_post", "delete"]) end)
  end

  test "propagation works in both directions", %{a: a, b: b} do
    :ok = EnforcerServer.add_policy(b, {:p, ["bob", "comment", "write"]})
    eventually(fn -> EnforcerServer.allow?(a, ["bob", "comment", "write"]) end)

    :ok = EnforcerServer.add_policy(a, {:p, ["eve", "comment", "read"]})
    eventually(fn -> EnforcerServer.allow?(b, ["eve", "comment", "read"]) end)
  end
end
