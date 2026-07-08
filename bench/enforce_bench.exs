# Single-caller enforce latency across models and policy-set sizes.
#
# Run with: mix run bench/enforce_bench.exs
Code.require_file("helpers.exs", __DIR__)

alias Casbin.Bench.Helpers
alias Casbin.Enforcer

sizes = [1_000, 10_000, 50_000]

IO.puts("Building fixtures...")

fixtures =
  for n <- sizes, into: %{} do
    {n, %{acl: Helpers.acl(n), keymatch2: Helpers.keymatch2(n), rbac: Helpers.rbac(n)}}
  end

jobs =
  for n <- sizes, reduce: %{} do
    acc ->
      %{acl: acl, keymatch2: km2, rbac: rbac} = fixtures[n]
      %{hit_head: hit_head, hit_tail: hit_tail, miss: miss} = Helpers.acl_requests(n)

      Map.merge(acc, %{
        "acl #{n} hit-head" => fn -> Enforcer.allow?(acl, hit_head) end,
        "acl #{n} hit-tail" => fn -> Enforcer.allow?(acl, hit_tail) end,
        "acl #{n} miss" => fn -> Enforcer.allow?(acl, miss) end,
        "keymatch2 #{n} hit-head" => fn ->
          Enforcer.allow?(km2, ["sub#{n - 1}", "/res#{n - 1}/42", "GET"])
        end,
        "keymatch2 #{n} miss" => fn -> Enforcer.allow?(km2, ["nobody", "/nothing/42", "GET"]) end,
        "rbac #{n} hit" => fn -> Enforcer.allow?(rbac, ["user1", "obj1", "read"]) end,
        "rbac #{n} miss" => fn -> Enforcer.allow?(rbac, ["user1", "nothing", "read"]) end
      })
  end

Benchee.run(jobs, time: 2, warmup: 1, memory_time: 0.5)
