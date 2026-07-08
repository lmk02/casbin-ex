# Multi-Instance Policy Synchronization (Watchers)

Casbin-Ex keeps policies in memory per BEAM instance. When several service
instances share the same policy storage, a mutation on instance A is
persisted to the database, but instances B and C keep serving their stale
in-memory copy — nothing tells them the database changed.

A **watcher** closes that gap. After every successful policy mutation the
originating instance publishes a `Casbin.Watcher.Event`; every other
instance applies the event to its in-memory state, or falls back to a full
reload from storage when the event cannot be applied safely.

Three backends ship with the library (all optional dependencies):

| Backend | Transport | Latency | Requirements |
|---|---|---|---|
| `Casbin.Watcher.RedisWatcher` | Redis pub/sub | milliseconds | `{:redix, "~> 1.5"}` |
| `Casbin.Watcher.PostgresWatcher` | Postgres LISTEN/NOTIFY | milliseconds | `{:postgrex, ...}`, direct DB session (no PgBouncer transaction pooling) |
| `Casbin.Watcher.PollingWatcher` | revision polling | poll interval | none |

**Recommendation:** RedisWatcher when Redis is available — it is independent
of your database connection topology (LISTEN/NOTIFY breaks behind PgBouncer
transaction pooling) and mirrors the proven upstream `casbin/redis-watcher`
design. Whichever backend you choose, the database remains the source of
truth: events are invalidation hints, and any gap or disconnect triggers a
reload.

On Elixir < 1.18 also add `{:jason, "~> 1.4"}` for the JSON event codec.

## Migrations

Two tables. `casbin_rule` (see the README) **must** have the unique index —
without it, concurrent inserts from different instances create duplicate
rows that `on_conflict: :nothing` cannot prevent.

The watcher additionally uses a revision counter for ordering and drift
detection:

```elixir
defmodule MyApp.Repo.Migrations.CreateCasbinRevision do
  use Ecto.Migration

  def change do
    create table(:casbin_revision, primary_key: false) do
      add :scope, :text, primary_key: true
      add :revision, :bigint, null: false, default: 0
      add :updated_at, :utc_datetime_usec, null: false
    end
  end
end
```

Every published event carries a revision from this counter. Receivers drop
duplicates (`revision <= own`), apply the next increment, and treat jumps
(`revision > own + 1`) as missed updates — triggering a reload instead of
silently diverging. The reconciliation timer compares this single row
against memory, so steady-state drift detection costs one primary-key read
per interval instead of re-reading the whole policy table.

## Wiring

Start one watcher process per enforcer, then wire the enforcer with
`adapter` + `watcher` so the startup order is right by construction —
subscribe **before** loading, so a change committed by a peer during the
initial load arrives as an (idempotent) event instead of being missed:

```elixir
# In your application supervision tree, after the Repo:
children = [
  MyApp.Repo,
  {Casbin.Watcher.RedisWatcher,
   name: :acl_watcher,
   enforcer: "acl",
   redis: [host: "redis.internal", port: 6379],   # or a redis:// URL string
   repo: MyApp.Repo,                               # enables reconciliation
   reconcile_interval: :timer.minutes(5)},
  ...
]

# Then start the enforcer (e.g. in a startup task):
{:ok, _pid} =
  Casbin.EnforcerSupervisor.start_enforcer("acl", "priv/casbin/model.conf",
    adapter: Casbin.Persist.EctoAdapter.new(MyApp.Repo),
    watcher: {Casbin.Watcher.RedisWatcher, :acl_watcher}
  )
```

`start_enforcer/3` wires adapter → watcher → load before the first
`allow?/2` is answered. The manual equivalent (same order!) is:

```elixir
Casbin.EnforcerSupervisor.start_enforcer("acl", "priv/casbin/model.conf")
Casbin.EnforcerServer.set_persist_adapter("acl", Casbin.Persist.EctoAdapter.new(MyApp.Repo))
Casbin.EnforcerServer.set_watcher("acl", {Casbin.Watcher.RedisWatcher, :acl_watcher})
Casbin.EnforcerServer.load_policies("acl")
Casbin.EnforcerServer.load_mapping_policies("acl")
```

All instances sharing a policy set must use the same channel (defaults to
`"casbin:policy:<enforcer name>"`, so identical enforcer names suffice).

After wiring, nothing else changes for your code: keep using
`EnforcerServer.add_policy/2`, `remove_policy/2`, `add_mapping_policy/2`,
etc. Every successful mutation is persisted, revision-stamped and published
automatically; peer instances converge within milliseconds.

## Failure modes and how they heal

| Failure | Effect | Healing |
|---|---|---|
| Redis briefly unreachable during publish | peers stay stale | reconciliation reload (revision mismatch) |
| Subscriber disconnected (deploy, Redis restart) | events published meanwhile are lost | automatic reload on re-subscribe |
| Event lost or delivered out of order | revision gap on receiver | reload instead of incremental apply |
| Quiet drift (any missed path) | memory ≠ storage | periodic revision poll → reload on mismatch |
| Redis down entirely | enforcement continues on current state | watcher logs, reconnects, reloads when back |

Authorization keeps serving from memory through all of these — a watcher
outage degrades freshness, never availability.

## save_policies in multi-instance deployments

`EnforcerServer.save_policies/1` rewrites the entire `casbin_rule` table
(delete-all + reinsert). Concurrent incremental writes from other instances
during that window can be lost. Treat it as an administrative/bootstrap
operation: prefer incremental `add_policy`/`remove_policy` in production,
and if you must save, do it from one place while other instances only read.
Peers receive a `full_reload` event after a save.

## Writing a custom backend

Implement the `Casbin.Watcher` behaviour (`notify/2`,
`set_update_callback/2`, `instance_id/1`, `close/1`) and pass
`{YourModule, ref}` to `set_watcher/2`. Contract highlights (see the
moduledoc for details):

* `notify/2` must not block the calling enforcer process (publish via cast)
  and must not raise — storage is already updated; failures only delay
  peers until reconciliation.
* Drop events whose `instance_id` matches your own before invoking the
  callback (pub/sub echoes messages back to the publisher).
* After any delivery gap you cannot rule out (reconnect, restart), deliver
  `%Casbin.Watcher.Event{op: :full_reload}` — missed events are
  unrecoverable in fire-and-forget transports.
