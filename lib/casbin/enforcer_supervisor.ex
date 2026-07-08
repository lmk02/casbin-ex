defmodule Casbin.EnforcerSupervisor do
  @moduledoc """
  A supervisor that starts `Enforcer` processes dynamically.
  """

  use DynamicSupervisor

  def start_link(_args) do
    DynamicSupervisor.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def init(:ok) do
    DynamicSupervisor.init(strategy: :one_for_one)
  end

  @doc """
  Starts a new `Enforcer` process and supervises it.

  The optional third argument wires the enforcer before it serves its
  first request — see `Casbin.EnforcerServer.start_link/3`:

      Casbin.EnforcerSupervisor.start_enforcer("acl", cfile,
        adapter: EctoAdapter.new(MyApp.Repo),
        watcher: {Casbin.Watcher.RedisWatcher, :acl_watcher}
      )
  """
  def start_enforcer(ename, cfile, opts \\ []) do
    child_spec = %{
      id: Casbin.EnforcerServer,
      start: {Casbin.EnforcerServer, :start_link, [ename, cfile, opts]},
      restart: :permanent
    }

    DynamicSupervisor.start_child(__MODULE__, child_spec)
  end
end
