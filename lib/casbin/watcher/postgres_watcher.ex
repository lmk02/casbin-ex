defmodule Casbin.Watcher.PostgresWatcher do
  @moduledoc """
  `Casbin.Watcher` backend using Postgres LISTEN/NOTIFY (via
  `Postgrex.Notifications`, already available when your repo uses the
  Postgres adapter).

  Events are published from the application with `pg_notify/2` — not from
  row triggers, which would fire per row and cannot batch — so payloads
  are identical to the Redis backend. Payloads above the ~8000-byte
  NOTIFY limit are downgraded to a `full_reload` pointer.

  **Caveat:** the listening connection must be a direct session to the
  database. PgBouncer in transaction-pooling mode (common at scale)
  breaks LISTEN; prefer `Casbin.Watcher.RedisWatcher` in such setups.

  Notifications are delivered on commit but are not durable: anything
  sent while the listener is reconnecting is lost, so this watcher relies
  on the same revision-based reconciliation as the Redis backend (pass
  `:repo`; strongly recommended here).

  ## Options

    * `:name` (required) — registered process name / watcher ref
    * `:enforcer` (required) — the enforcer name this watcher serves
    * `:repo` (required) — Ecto repo; used to emit `pg_notify` and to
      reconcile revisions
    * `:channel` — NOTIFY channel, default `"casbin_policy_<enforcer>"`
      (Postgres channel names are identifiers — no colons)
    * `:reconcile_interval` — milliseconds between revision checks,
      default 1 minute; `nil` disables
  """

  @behaviour Casbin.Watcher

  use GenServer

  require Logger

  alias Casbin.EnforcerServer
  alias Casbin.Persist.Revision
  alias Casbin.Watcher
  alias Casbin.Watcher.Event
  alias Ecto.Adapters.SQL

  @default_reconcile_interval :timer.minutes(1)
  # pg_notify payloads are capped at 8000 bytes; leave headroom
  @max_payload_bytes 7_900

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))
  end

  def child_spec(opts) do
    %{id: Keyword.get(opts, :name, __MODULE__), start: {__MODULE__, :start_link, [opts]}}
  end

  #
  # Casbin.Watcher callbacks
  #

  @impl Casbin.Watcher
  def notify(ref, %Event{} = event) do
    GenServer.cast(ref, {:publish, event})
  end

  @impl Casbin.Watcher
  def set_update_callback(ref, callback) when is_function(callback, 1) do
    GenServer.call(ref, {:set_update_callback, callback})
  end

  @impl Casbin.Watcher
  def instance_id(ref), do: GenServer.call(ref, :instance_id)

  @impl Casbin.Watcher
  def close(ref), do: GenServer.stop(ref)

  #
  # GenServer callbacks
  #

  @impl GenServer
  def init(opts) do
    ensure_postgrex!()

    enforcer = Keyword.fetch!(opts, :enforcer)
    repo = Keyword.fetch!(opts, :repo)
    channel = opts |> Keyword.get(:channel, default_channel(enforcer)) |> validate_channel!()

    # apply/3 keeps these dynamic: postgrex is an optional dependency, and
    # a static remote call would emit an undefined-module compile warning
    # in host projects that do not include it.
    # credo:disable-for-lines:6 Credo.Check.Refactor.Apply
    {:ok, listener} =
      apply(Postgrex.Notifications, :start_link, [
        repo.config() |> Keyword.put(:auto_reconnect, true)
      ])

    {:ok, _listen_ref} = apply(Postgrex.Notifications, :listen, [listener, channel])

    state = %{
      enforcer: enforcer,
      repo: repo,
      channel: channel,
      listener: listener,
      instance_id: Watcher.generate_instance_id(),
      callback: Keyword.get(opts, :callback),
      reconcile_interval: Keyword.get(opts, :reconcile_interval, @default_reconcile_interval)
    }

    schedule_reconcile(state)
    {:ok, state}
  end

  @impl GenServer
  def handle_cast({:publish, %Event{} = event}, state) do
    event = %{event | instance_id: event.instance_id || state.instance_id}
    payload = Event.encode!(event)

    payload =
      if byte_size(payload) > @max_payload_bytes do
        # Too big for NOTIFY: send a pointer instead of the data.
        Event.encode!(%Event{
          op: :full_reload,
          instance_id: event.instance_id,
          revision: event.revision,
          enforcer: event.enforcer
        })
      else
        payload
      end

    case SQL.query(state.repo, "SELECT pg_notify($1::text, $2::text)", [
           state.channel,
           payload
         ]) do
      {:ok, _result} ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "casbin: PostgresWatcher failed to publish #{event.op} for '#{state.enforcer}': " <>
            "#{inspect(reason)}; peers converge via reconciliation reload"
        )
    end

    {:noreply, state}
  end

  @impl GenServer
  def handle_call({:set_update_callback, callback}, _from, state) do
    {:reply, :ok, %{state | callback: callback}}
  end

  def handle_call(:instance_id, _from, state) do
    {:reply, state.instance_id, state}
  end

  @impl GenServer
  def handle_info({:notification, _pid, _ref, channel, payload}, %{channel: channel} = state) do
    case Event.decode(payload) do
      {:ok, %Event{instance_id: id}} when id == state.instance_id ->
        :ok

      {:ok, %Event{} = event} ->
        deliver(state, event)

      {:error, reason} ->
        Logger.warning(
          "casbin: PostgresWatcher for '#{state.enforcer}' dropped malformed payload: " <>
            inspect(reason)
        )
    end

    {:noreply, state}
  end

  def handle_info(:reconcile, state) do
    reconcile(state)
    schedule_reconcile(state)
    {:noreply, state}
  end

  def handle_info(message, state) do
    Logger.debug("casbin: PostgresWatcher ignoring message: #{inspect(message)}")
    {:noreply, state}
  end

  #
  # Helpers
  #

  defp default_channel(enforcer) do
    "casbin_policy_" <> String.replace(enforcer, ~r/[^a-zA-Z0-9_]/, "_")
  end

  # The channel name reaches a LISTEN statement; restrict it to a plain
  # identifier so it can never smuggle SQL (CVE-2026-32687 hardened
  # Postgrex, but validate regardless of the installed version).
  defp validate_channel!(channel) when is_binary(channel) do
    if channel =~ ~r/^[a-zA-Z_][a-zA-Z0-9_]*$/ do
      channel
    else
      raise ArgumentError,
            "invalid Postgres NOTIFY channel #{inspect(channel)}: " <>
              "only [a-zA-Z0-9_] identifiers are allowed"
    end
  end

  defp deliver(%{callback: nil}, _event), do: :ok

  defp deliver(%{callback: callback} = state, event) do
    callback.(event)
  rescue
    error ->
      Logger.warning(
        "casbin: PostgresWatcher callback failed for '#{state.enforcer}': #{inspect(error)}"
      )
  catch
    :exit, reason ->
      Logger.warning(
        "casbin: PostgresWatcher callback exited for '#{state.enforcer}': #{inspect(reason)}"
      )
  end

  defp reconcile(%{callback: nil}), do: :ok

  defp reconcile(state) do
    with {:ok, db_revision} <- Revision.current(state.repo, state.enforcer),
         own_revision = EnforcerServer.get_revision(state.enforcer),
         true <- db_revision != own_revision do
      Logger.info(
        "casbin: PostgresWatcher for '#{state.enforcer}' detected drift " <>
          "(storage at #{db_revision}, memory at #{own_revision}); reloading"
      )

      deliver(state, %Event{op: :full_reload, revision: db_revision})
    end

    :ok
  rescue
    error ->
      Logger.warning("casbin: PostgresWatcher reconciliation failed: #{inspect(error)}")
  catch
    :exit, reason ->
      Logger.warning("casbin: PostgresWatcher reconciliation exited: #{inspect(reason)}")
  end

  defp schedule_reconcile(%{reconcile_interval: nil}), do: :ok

  defp schedule_reconcile(%{reconcile_interval: interval}) when is_integer(interval) do
    Process.send_after(self(), :reconcile, interval)
  end

  defp ensure_postgrex! do
    unless Code.ensure_loaded?(Postgrex.Notifications) do
      raise ArgumentError,
            "Casbin.Watcher.PostgresWatcher requires the :postgrex package. " <>
              ~s(Add {:postgrex, ">= 0.0.0"} to your dependencies.)
    end
  end
end
