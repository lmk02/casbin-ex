defmodule Casbin.Watcher.PollingWatcher do
  @moduledoc """
  `Casbin.Watcher` backend that only polls the `casbin_revision` table —
  no message broker required.

  Each poll is a single primary-key read; when the stored revision
  differs from the enforcer's applied revision, the enforcer reloads all
  policies from storage. Change propagation latency equals the poll
  interval, so this backend suits deployments without Redis (or a
  LISTEN-able Postgres connection) that can tolerate seconds of staleness.

  Publishing is a no-op: the revision bump performed by the mutating
  `Casbin.EnforcerServer` is itself the signal that peers poll for.

  ## Options

    * `:name` (required) — registered process name / watcher ref
    * `:enforcer` (required) — the enforcer name this watcher serves
    * `:repo` (required) — Ecto repo used to read `casbin_revision`
    * `:poll_interval` — milliseconds between polls, default 10 seconds
  """

  @behaviour Casbin.Watcher

  use GenServer

  require Logger

  alias Casbin.EnforcerServer
  alias Casbin.Persist.Revision
  alias Casbin.Watcher
  alias Casbin.Watcher.Event

  @default_poll_interval :timer.seconds(10)

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
  def notify(_ref, %Event{}), do: :ok

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
    state = %{
      enforcer: Keyword.fetch!(opts, :enforcer),
      repo: Keyword.fetch!(opts, :repo),
      poll_interval: Keyword.get(opts, :poll_interval, @default_poll_interval),
      instance_id: Watcher.generate_instance_id(),
      callback: Keyword.get(opts, :callback)
    }

    schedule_poll(state)
    {:ok, state}
  end

  @impl GenServer
  def handle_call({:set_update_callback, callback}, _from, state) do
    {:reply, :ok, %{state | callback: callback}}
  end

  def handle_call(:instance_id, _from, state) do
    {:reply, state.instance_id, state}
  end

  @impl GenServer
  def handle_info(:poll, state) do
    poll(state)
    schedule_poll(state)
    {:noreply, state}
  end

  def handle_info(message, state) do
    Logger.debug("casbin: PollingWatcher ignoring message: #{inspect(message)}")
    {:noreply, state}
  end

  defp poll(%{callback: nil}), do: :ok

  defp poll(state) do
    with {:ok, db_revision} <- Revision.current(state.repo, state.enforcer),
         own_revision = EnforcerServer.get_revision(state.enforcer),
         true <- db_revision != own_revision do
      state.callback.(%Event{op: :full_reload, revision: db_revision})
    end

    :ok
  rescue
    error ->
      Logger.warning("casbin: PollingWatcher poll failed: #{inspect(error)}")
  catch
    :exit, reason ->
      Logger.warning("casbin: PollingWatcher poll exited: #{inspect(reason)}")
  end

  defp schedule_poll(%{poll_interval: interval}) do
    Process.send_after(self(), :poll, interval)
  end
end
