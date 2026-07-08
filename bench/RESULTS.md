# Benchmark results

Machine: Apple Silicon, 12 schedulers, Erlang/OTP 27.3, Elixir 1.18.3.
Numbers from `bench/*.exs` and ad-hoc `:timer.tc` runs during the 1.7.0
performance work; re-run locally with `mix run bench/enforce_bench.exs`
etc. — absolute values vary by machine, the ratios are the point.

## EnforcerServer.allow? at 50,000 policies (v1.7.0)

| Scenario | before (full scan through GenServer) | after (indexed, lock-free) |
|---|---|---|
| ACL exact-match hit | ~10 ms | **6.8 µs** |
| ACL miss | ~20 ms | **3.0 µs** |
| RBAC hit (100 roles, deep chains) | ~56 ms | **17–110 µs** |
| RBAC miss | ~56 ms | **110 µs** |

The "after" path: `Casbin.Runtime` evaluates in the caller process
against the `Casbin.Store` ETS projection, probing only the policy
buckets derivable from the matcher's index plan
(`Casbin.Model.MatcherAnalysis`). RBAC costs scale with the number of
reachable roles (bucket probes), not the policy count.

## Concurrent read throughput (10k policies, ACL)

| Concurrent callers | before (all reads serialize through one GenServer) | after |
|---|---|---|
| 1 | ~220 k/s | ~220 k/s |
| 4 | capped by the single process | ~343 k/s |
| 12 | capped by the single process | ~448 k/s |

## Bulk loading

* 50k rules through `EnforcerServer.add_policy/2` one by one: previously
  effectively unbounded (O(n²): per-rule `Enum.member?` dedup plus a
  full-struct ETS copy per mutation — a 50k load did not finish in 10
  minutes); now **~3.2 s**. Prefer `add_policies/3` or
  `load_policies/1`, which batch further.

## Pattern-matching models (keyMatch2/regexMatch/globMatch)

Regexes are compiled once per distinct pattern
(`Casbin.Internal.PatternCache`) instead of once per policy per request:
~0.8 µs per (request × policy) pair after warm-up, where each pair
previously paid one or two `Regex.compile/1` calls (tens of µs). Pattern
models have no index plan and use the chunked full scan with
short-circuiting.

## Role graphs

`g(...)` used to run a full DFS per (request × policy) pair; reachable
sets are now memoized per role-graph version, so the DFS runs once per
role mutation per source vertex.
