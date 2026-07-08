defmodule Casbin.TestWatcher do
  @moduledoc """
  In-process `Casbin.Watcher` implementation for tests.

  Published events are forwarded to the configured test pid as
  `{:notified, event}` messages; `deliver/2` simulates an event arriving
  from a peer instance by invoking the installed update callback.
  """

  @behaviour Casbin.Watcher

  use Agent

  def start_link(opts) do
    test_pid = Keyword.fetch!(opts, :test_pid)
    name = Keyword.fetch!(opts, :name)

    Agent.start_link(
      fn ->
        %{
          test_pid: test_pid,
          callback: nil,
          instance_id: Casbin.Watcher.generate_instance_id()
        }
      end,
      name: name
    )
  end

  @impl true
  def notify(name, event) do
    send(Agent.get(name, & &1.test_pid), {:notified, event})
    :ok
  end

  @impl true
  def set_update_callback(name, callback) do
    Agent.update(name, &%{&1 | callback: callback})
  end

  @impl true
  def instance_id(name), do: Agent.get(name, & &1.instance_id)

  @impl true
  def close(name), do: Agent.stop(name)

  @doc "Simulates receiving `event` from a peer instance."
  def deliver(name, event) do
    callback = Agent.get(name, & &1.callback)
    callback.(event)
  end
end
