defmodule Casbin.Watcher.RedisWatcher do
  @moduledoc """
  `Casbin.Watcher` backend using Redis pub/sub (via the optional `:redix`
  dependency).

  Every enforcer instance runs one `RedisWatcher` process subscribed to a
  shared channel. Policy mutations are published as JSON
  `Casbin.Watcher.Event` payloads; events published by other instances
  are delivered to the enforcer through `Casbin.EnforcerServer.set_watcher/2`.

  Redis pub/sub is fire-and-forget: everything published while a
  subscriber is disconnected is lost. The watcher therefore triggers a
  full policy reload on every re-subscription after a disconnect, and can
  additionally reconcile periodically against the `casbin_revision` table
  (pass a `:repo`) to heal quiet drift with one cheap query per interval.

  ## Options

    * `:name` (required) — registered process name; also the watcher ref:
      `EnforcerServer.set_watcher(ename, {RedisWatcher, name})`
    * `:enforcer` (required) — the enforcer name this watcher serves
    * `:redis` — Redix connection options (keyword) or a Redis URL string
    * `:channel` — pub/sub channel, default `"casbin:policy:<enforcer>"`;
      all instances sharing the policy set must use the same channel
    * `:repo` — Ecto repo for revision-based reconciliation (optional)
    * `:reconcile_interval` — milliseconds between revision checks,
      default 5 minutes; `nil` disables

  ## Example

      children = [
        MyApp.Repo,
        {Casbin.Watcher.RedisWatcher,
         name: :acl_watcher,
         enforcer: "acl",
         redis: [host: "redis.internal", port: 6379],
         repo: MyApp.Repo}
      ]
  """

  @behaviour Casbin.Watcher

  use GenServer

  require Logger

  alias Casbin.EnforcerServer
  alias Casbin.Persist.Revision
  alias Casbin.Watcher
  alias Casbin.Watcher.Event

  @default_reconcile_interval :timer.minutes(5)

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))
  end

  def child_spec(opts) do
    %{id: Keyword.get(opts, :name, __MODULE__), start: {__MODULE__, :start_link, [opts]}}
  end

  @doc """
  Blocks until the initial subscription is confirmed, so callers can load
  policies knowing no update will be missed. Raises on timeout.
  """
  def await_ready(ref, timeout \\ 5_000) do
    GenServer.call(ref, :await_ready, timeout)
  end

  #
  # Casbin.Watcher callbacks
  #

  @impl Casbin.Watcher
  def notify(ref, %Event{} = event) do
    # Cast, not call: the enforcer process publishes while handling a
    # mutation and must never block on this process (see Casbin.Watcher).
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
    ensure_redix!()

    enforcer = Keyword.fetch!(opts, :enforcer)
    channel = Keyword.get(opts, :channel, "casbin:policy:#{enforcer}")
    redis = Keyword.get(opts, :redis, [])

    # apply/3 keeps these dynamic: Redix is an optional dependency, and a
    # static remote call would emit an undefined-module compile warning in
    # host projects that do not include it.
    # credo:disable-for-lines:4 Credo.Check.Refactor.Apply
    {:ok, pub_conn} = apply(Redix, :start_link, [redis])
    {:ok, pubsub_conn} = apply(Redix.PubSub, :start_link, [redis])
    {:ok, _subscription} = apply(Redix.PubSub, :subscribe, [pubsub_conn, channel, self()])

    state = %{
      enforcer: enforcer,
      channel: channel,
      pub_conn: pub_conn,
      pubsub_conn: pubsub_conn,
      instance_id: Watcher.generate_instance_id(),
      callback: Keyword.get(opts, :callback),
      repo: Keyword.get(opts, :repo),
      reconcile_interval: Keyword.get(opts, :reconcile_interval, @default_reconcile_interval),
      subscribed_once?: false,
      ready?: false,
      awaiting: []
    }

    schedule_reconcile(state)
    {:ok, state}
  end

  @impl GenServer
  def handle_cast({:publish, %Event{} = event}, state) do
    event = %{event | instance_id: event.instance_id || state.instance_id}

    # credo:disable-for-lines:2 Credo.Check.Refactor.Apply
    case apply(Redix, :command, [state.pub_conn, ["PUBLISH", state.channel, Event.encode!(event)]]) do
      {:ok, _receivers} ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "casbin: RedisWatcher failed to publish #{event.op} for '#{state.enforcer}': " <>
            "#{inspect(reason)}; peers converge via reconnect/reconciliation reload"
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

  def handle_call(:await_ready, from, state) do
    if state.ready? do
      {:reply, :ok, state}
    else
      {:noreply, %{state | awaiting: [from | state.awaiting]}}
    end
  end

  @impl GenServer
  def handle_info({:redix_pubsub, _pid, _ref, :subscribed, _props}, state) do
    # Any subscription after the first means we reconnected: everything
    # published in between is gone for good, so resynchronize from storage.
    if state.subscribed_once? do
      Logger.info("casbin: RedisWatcher for '#{state.enforcer}' resubscribed; reloading policies")
      fire_full_reload(state)
    end

    Enum.each(state.awaiting, &GenServer.reply(&1, :ok))
    {:noreply, %{state | subscribed_once?: true, ready?: true, awaiting: []}}
  end

  def handle_info({:redix_pubsub, _pid, _ref, :disconnected, props}, state) do
    Logger.warning(
      "casbin: RedisWatcher for '#{state.enforcer}' disconnected from Redis " <>
        "(#{inspect(props)}); serving possibly stale policies until resubscribed"
    )

    {:noreply, %{state | ready?: false}}
  end

  def handle_info({:redix_pubsub, _pid, _ref, :message, %{payload: payload}}, state) do
    case Event.decode(payload) do
      {:ok, %Event{instance_id: id}} when id == state.instance_id ->
        :ok

      {:ok, %Event{} = event} ->
        deliver(state, event)

      {:error, reason} ->
        Logger.warning(
          "casbin: RedisWatcher for '#{state.enforcer}' dropped malformed payload: " <>
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
    Logger.debug("casbin: RedisWatcher ignoring message: #{inspect(message)}")
    {:noreply, state}
  end

  #
  # Helpers
  #

  defp deliver(%{callback: nil}, _event), do: :ok

  defp deliver(%{callback: callback} = state, event) do
    callback.(event)
  rescue
    error ->
      Logger.warning(
        "casbin: RedisWatcher callback failed for '#{state.enforcer}': #{inspect(error)}"
      )
  catch
    :exit, reason ->
      Logger.warning(
        "casbin: RedisWatcher callback exited for '#{state.enforcer}': #{inspect(reason)}"
      )
  end

  defp fire_full_reload(state) do
    deliver(state, %Event{op: :full_reload, instance_id: "#{state.instance_id}:reload"})
  end

  # Compares the revision in storage with the enforcer's applied revision
  # and reloads on mismatch. One primary-key read per interval when in sync.
  defp reconcile(%{repo: nil}), do: :ok
  defp reconcile(%{callback: nil}), do: :ok

  defp reconcile(state) do
    with {:ok, db_revision} <- Revision.current(state.repo, state.enforcer),
         own_revision = EnforcerServer.get_revision(state.enforcer),
         true <- db_revision != own_revision do
      Logger.info(
        "casbin: RedisWatcher for '#{state.enforcer}' detected drift " <>
          "(storage at #{db_revision}, memory at #{own_revision}); reloading"
      )

      fire_full_reload(state)
    end

    :ok
  rescue
    error ->
      Logger.warning("casbin: RedisWatcher reconciliation failed: #{inspect(error)}")
  catch
    :exit, reason ->
      Logger.warning("casbin: RedisWatcher reconciliation exited: #{inspect(reason)}")
  end

  defp schedule_reconcile(%{reconcile_interval: nil}), do: :ok
  defp schedule_reconcile(%{repo: nil}), do: :ok

  defp schedule_reconcile(%{reconcile_interval: interval}) when is_integer(interval) do
    Process.send_after(self(), :reconcile, interval)
  end

  defp ensure_redix! do
    unless Code.ensure_loaded?(Redix) do
      raise ArgumentError,
            "Casbin.Watcher.RedisWatcher requires the :redix package. " <>
              ~s(Add {:redix, "~> 1.5"} to your dependencies.)
    end
  end
end
