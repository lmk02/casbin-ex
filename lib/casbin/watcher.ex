defmodule Casbin.Watcher do
  @moduledoc """
  Behaviour for propagating policy changes between enforcer instances
  that share the same policy storage.

  Casbin-Ex keeps policies in memory per instance. When one instance
  mutates a policy the change is persisted through the adapter, but other
  instances would keep serving their stale in-memory copy. A watcher
  closes that gap: the mutating instance publishes a
  `Casbin.Watcher.Event` after each successful write, and every other
  instance applies the event to its own in-memory state (or performs a
  full reload from storage when the event cannot be applied safely).

  A configured watcher is referenced as `{module, ref}` where `ref`
  identifies the backend instance (usually a registered process name).
  See `Casbin.Watcher.RedisWatcher` for the primary backend.

  Implementations must guarantee:

    * `notify/2` never raises into the caller and never blocks on the
      enforcer process (the enforcer calls `notify/2` while handling a
      mutation, and the watcher calls back into the enforcer when events
      arrive — a synchronous round-trip in both directions deadlocks).
      Process-based watchers should publish via a cast. Publishing
      failures are logged, not raised: the local mutation already
      succeeded and storage is the source of truth.
    * received events are delivered to the callback installed with
      `set_update_callback/2`, excluding events published by the same
      instance (compare `instance_id`).
    * after any gap in delivery (reconnect, restart), the callback is
      invoked with a `%Event{op: :full_reload}` since missed events are
      gone for good.
  """

  alias Casbin.Watcher.Event

  @type ref :: term()
  @type t :: {module(), ref()}

  @doc "Publishes an event to all peer instances."
  @callback notify(ref(), Event.t()) :: :ok | {:error, term()}

  @doc "Installs the function invoked for every event received from peers."
  @callback set_update_callback(ref(), (Event.t() -> any())) :: :ok

  @doc "Returns the unique id this watcher stamps on published events."
  @callback instance_id(ref()) :: String.t() | nil

  @doc "Shuts the watcher down."
  @callback close(ref()) :: :ok

  @spec notify(t(), Event.t()) :: :ok | {:error, term()}
  def notify({module, ref}, %Event{} = event), do: module.notify(ref, event)

  @spec set_update_callback(t(), (Event.t() -> any())) :: :ok
  def set_update_callback({module, ref}, callback) when is_function(callback, 1),
    do: module.set_update_callback(ref, callback)

  @spec instance_id(t()) :: String.t() | nil
  def instance_id({module, ref}), do: module.instance_id(ref)

  @spec close(t()) :: :ok
  def close({module, ref}), do: module.close(ref)

  @doc """
  Generates a random instance id for self-suppression of published events.
  """
  @spec generate_instance_id() :: String.t()
  def generate_instance_id do
    Base.url_encode64(:crypto.strong_rand_bytes(12))
  end
end
