# Bulk policy loading cost (used to be O(n^2) via per-rule Enum.member?).
#
# Run with: mix run bench/load_bench.exs
Code.require_file("helpers.exs", __DIR__)

alias Casbin.Bench.Helpers

Benchee.run(
  %{
    "bulk add via add_policy!" => fn n -> Helpers.acl(n) end
  },
  inputs: %{"1k" => 1_000, "10k" => 10_000, "50k" => 50_000},
  time: 2,
  warmup: 1
)
