# Concurrent enforce throughput through EnforcerServer.
#
# Every allow? call round-trips the per-enforcer GenServer, so throughput
# should stay flat as `parallel` grows until reads stop serializing
# through the server process. This is the number the lock-free read path
# has to move.
#
# Run with: mix run bench/concurrency_bench.exs
Code.require_file("helpers.exs", __DIR__)

alias Casbin.Bench.Helpers

n = 10_000
ename = "bench_acl"

{:ok, _pid} = Casbin.EnforcerSupervisor.start_enforcer(ename, Helpers.conf("acl.conf"))

Enum.each(0..(n - 1), fn i ->
  Casbin.EnforcerServer.add_policy(ename, {:p, ["sub#{i}", "obj#{i}", "read"]})
end)

req = ["sub#{n - 1}", "obj#{n - 1}", "read"]

for parallel <- [1, 4, System.schedulers_online()] do
  IO.puts("\n=== parallel: #{parallel} ===")

  Benchee.run(
    %{"EnforcerServer.allow? (#{n} rules)" => fn -> Casbin.EnforcerServer.allow?(ename, req) end},
    time: 2,
    warmup: 1,
    parallel: parallel
  )
end
