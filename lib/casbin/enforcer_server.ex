defmodule Casbin.EnforcerServer do
  @moduledoc """
  An enforcer process that holds an `Enforcer` struct as its state.
  """

  use GenServer

  require Logger

  alias Casbin.Enforcer
  alias Casbin.Persist.EctoAdapter
  alias Casbin.Persist.Revision
  alias Casbin.Store
  alias Casbin.Watcher
  alias Casbin.Watcher.Event

  #
  # Client Public Interface
  #

  @doc """
  Loads and constructs an enforcer from the given config file `cfile`,
  and spawns a new process under the given name `ename` taking the
  (just constructed) enforcer as its initial state.

  Accepts optional wiring performed before the first request is served
  (calls queue until wiring completes):

    * `:adapter` — persist adapter to set
    * `:watcher` — `{module, ref}` watcher to install; when the watcher
      module exports `await_ready/1` it is awaited before loading, so no
      update published during the initial load is missed
    * `:load` — load policies and mapping policies from the adapter
      (default `true` when `:adapter` is given)

  ## Examples

      EnforcerServer.start_link("acl", cfile,
        adapter: EctoAdapter.new(MyApp.Repo),
        watcher: {Casbin.Watcher.RedisWatcher, :acl_watcher}
      )
  """
  def start_link(ename, cfile, opts \\ []) do
    GenServer.start_link(
      __MODULE__,
      {ename, cfile, opts},
      name: via_tuple(ename)
    )
  end

  @doc """
  Returns `true` if the given request `req` is allowed under the enforcer
  whose name given by `ename`.

  Returns `false`, otherwise.

  The check is evaluated in the calling process against the shared
  `Casbin.Store` projection, so concurrent checks do not serialize
  through the enforcer process. Mutations update the projection before
  they return, so a caller always sees its own writes.

  See `Enforcer.allow?/2` for more information.
  """
  def allow?(ename, req) do
    case Casbin.Runtime.enforce(ename, req) do
      {:ok, allowed} ->
        allowed

      :no_projection ->
        GenServer.call(via_tuple(ename), {:allow?, req})
    end
  end

  @doc """
  Adds a new policy rule with key given by `key` and a list of
  attribute values `attr_values` to the enforcer.

  See `Enforcer.add_policy/2` for more information.
  """
  def add_policy(ename, {key, attrs}) do
    GenServer.call(via_tuple(ename), {:add_policy, {key, attrs}})
  end

  @doc """
  Removes the matching policy rule or rules with key given by `key` and a list of
  attribute values `attr_values` to the enforcer.

  See `Enforcer.remove_policy/2` for more information.
  """
  def remove_policy(ename, {key, attrs}) do
    GenServer.call(via_tuple(ename), {:remove_policy, {key, attrs}})
  end

  @doc """
  Adds a batch of policy rules sharing the policy key `key` in one call:
  one batched storage write and a single watcher event.

  See `Enforcer.add_policies/2` for more information.
  """
  def add_policies(ename, key, attrs_list) when is_atom(key) and is_list(attrs_list) do
    GenServer.call(via_tuple(ename), {:add_policies, key, attrs_list})
  end

  @doc """
  Removes a batch of policy rules sharing the policy key `key` in one
  call. Rules that are not present are ignored.

  See `Enforcer.remove_policies/2` for more information.
  """
  def remove_policies(ename, key, attrs_list) when is_atom(key) and is_list(attrs_list) do
    GenServer.call(via_tuple(ename), {:remove_policies, key, attrs_list})
  end

  @doc """
  Loads policy rules from the configured persist adapter and adds them
  to the enforcer.

  The persist adapter must be set using `set_persist_adapter/2` before
  calling this function, otherwise an error will be returned.

  ## Examples

      # Set an EctoAdapter and load policies from database
      adapter = EctoAdapter.new(MyApp.Repo)
      EnforcerServer.set_persist_adapter("my_enforcer", adapter)
      EnforcerServer.load_policies("my_enforcer")

  See `Enforcer.load_policies!/1` for more details.
  """
  def load_policies(ename) do
    GenServer.call(via_tuple(ename), {:load_policies})
  end

  @doc """
  Loads policy rules from external file given by the name `pfile` and
  adds them to the enforcer.

  See `Enforcer.load_policies!/2` for more details.
  """
  def load_policies(ename, pfile) do
    GenServer.call(via_tuple(ename), {:load_policies, pfile})
  end

  @doc """
  Loads filtered policies from the persist adapter.
  Only policies matching the filter are loaded into the enforcer.

  See `Enforcer.load_filtered_policies!/2` for more details.
  """
  def load_filtered_policies(ename, filter) do
    GenServer.call(via_tuple(ename), {:load_filtered_policies, filter})
  end

  @doc """
  Returns a list of policies in the given enforcer that match the
  given criteria.

  See `Enforcer.list_policies/2` for more details.
  """
  def list_policies(ename, criteria) do
    GenServer.call(via_tuple(ename), {:list_policies, criteria})
  end

  @doc """
  Saves the current set of policies using the configured PersistAdapter.

  See `Enforcer.save_policies/1`
  """
  def save_policies(ename) do
    GenServer.call(via_tuple(ename), {:save_policies})
  end

  @doc """
  Makes `role1` inherit from (or has role ) `role2`. The `mapping_name`
  should be one of the names given in the model configuration file under
  the `role_definition` section. For example if your role definition look
  like this:

  [role_definition]
  g = _, _

  then `mapping_name` should be the atom `:g`.

  See `Enforcer.add_mapping_policy/2` for more details.
  """
  def add_mapping_policy(ename, {mapping_name, role1, role2}) do
    GenServer.call(
      via_tuple(ename),
      {:add_mapping_policy, {mapping_name, role1, role2}}
    )
  end

  def add_mapping_policy(ename, {mapping_name, role1, role2, dom}) do
    GenServer.call(
      via_tuple(ename),
      {:add_mapping_policy, {mapping_name, role1, role2, dom}}
    )
  end

  @doc """
  Removes a mapping policy and its role inheritence. The `mapping_name`
  should be one of the names given in the model configuration file under
  the `role_definition` section. For example if your role definition look
  like this:

  [role_definition]
  g = _, _

  then `mapping_name` should be the atom `:g`.

  See `Enforcer.remove_mapping_policy/2` for more details.
  """
  def remove_mapping_policy(ename, {mapping_name, role1, role2}) do
    GenServer.call(
      via_tuple(ename),
      {:remove_mapping_policy, {mapping_name, role1, role2}}
    )
  end

  def remove_mapping_policy(ename, {mapping_name, role1, role2, dom}) do
    GenServer.call(
      via_tuple(ename),
      {:remove_mapping_policy, {mapping_name, role1, role2, dom}}
    )
  end

  @doc """
  Removes policies with attributes that match the filter fields
  starting at the index.any()

  see `Enforecer.remove_filtered_policy/4
  """
  def remove_filtered_policy(ename, req_key, idx, req) do
    GenServer.call(
      via_tuple(ename),
      {:remove_filtered_policy, req_key, idx, req}
    )
  end

  @doc """
  Loads mapping policies from the configured persist adapter and adds them
  to the enforcer.

  The persist adapter must be set using `set_persist_adapter/2` before
  calling this function, otherwise an error will be returned.

  ## Examples

      # Set an EctoAdapter and load mapping policies from database
      adapter = EctoAdapter.new(MyApp.Repo)
      EnforcerServer.set_persist_adapter("my_enforcer", adapter)
      EnforcerServer.load_mapping_policies("my_enforcer")

  See `Enforcer.load_mapping_policies!/1` for more details.
  """
  def load_mapping_policies(ename) do
    GenServer.call(via_tuple(ename), {:load_mapping_policies})
  end

  @doc """
  Loads mapping policies from a csv file and adds them to the enforcer.

  See `Enforcer.load_mapping_policies!/2` for more details.
  """
  def load_mapping_policies(ename, fname) do
    GenServer.call(via_tuple(ename), {:load_mapping_policies, fname})
  end

  @doc """
  Return a fresh enforcer.

  See `Enforcer.init/1` for more details.
  """
  def reset_configuration(ename, cfile) do
    GenServer.call(via_tuple(ename), {:reset_configuration, cfile})
  end

  @doc """
  Adds a user-defined function to the enforcer.

  See `Enforcer.add_fun/2` for more details.
  """
  def add_fun(ename, {fun_name, fun}) do
    GenServer.call(via_tuple(ename), {:add_fun, {fun_name, fun}})
  end

  @doc """
    Set the persist adapter for the enforcer. If not explicitly set the Enforcer
    will use a read-only file adapter for backwards compatibility.
  """
  def set_persist_adapter(ename, adapter) do
    GenServer.call(via_tuple(ename), {:set_persist_adapter, adapter})
  end

  @doc """
  Installs (or removes, when `nil`) a watcher for multi-instance policy
  synchronization.

  The watcher is a `{module, ref}` tuple; `module` implements the
  `Casbin.Watcher` behaviour. After a watcher is set, every successful
  policy mutation on this enforcer is published to peers, and events
  received from peers are applied to this enforcer's in-memory state.

  Set the watcher *before* calling `load_policies/1` so updates published
  during the initial load are not missed:

      EnforcerServer.set_persist_adapter("acl", EctoAdapter.new(MyApp.Repo))
      EnforcerServer.set_watcher("acl", {Casbin.Watcher.RedisWatcher, :acl_watcher})
      EnforcerServer.load_policies("acl")
      EnforcerServer.load_mapping_policies("acl")
  """
  def set_watcher(ename, nil) do
    GenServer.call(via_tuple(ename), {:set_watcher, nil, nil})
  end

  def set_watcher(ename, {_module, _ref} = watcher) do
    # Wire the watcher from the caller process: the enforcer process and
    # the watcher process call each other (notify vs. update callback), so
    # neither may ever block on the other.
    instance_id = Watcher.instance_id(watcher)
    :ok = Watcher.set_update_callback(watcher, fn event -> apply_watcher_event(ename, event) end)
    GenServer.call(via_tuple(ename), {:set_watcher, watcher, instance_id})
  end

  @doc """
  Applies a policy-change event received from a peer instance to the
  in-memory state, without persisting it again.

  This is normally invoked by the configured watcher, not by user code.
  Duplicate or stale events are dropped; events that indicate missed
  updates (revision gaps, `:full_reload`) trigger a reload from storage.
  """
  def apply_watcher_event(ename, %Event{} = event) do
    GenServer.call(via_tuple(ename), {:apply_watcher_event, event})
  end

  @doc """
  Discards the in-memory policies and reloads them from the persist
  adapter, preserving the adapter, watcher and user-defined functions.

  See `Enforcer.reload_policies!/1` for more details.
  """
  def reload_policies(ename) do
    GenServer.call(via_tuple(ename), {:reload_policies})
  end

  @doc """
  Returns the revision of the last applied policy change (0 when revision
  tracking is not in use).
  """
  def get_revision(ename) do
    GenServer.call(via_tuple(ename), {:get_revision})
  end

  #
  # Server Callbacks
  #

  def init({ename, cfile}), do: init({ename, cfile, []})

  def init({ename, cfile, opts}) do
    case create_new_or_lookup_enforcer(ename, cfile) do
      {:error, reason} ->
        {:stop, reason}

      {:ok, enforcer} ->
        Logger.info("Spawned an enforcer process named '#{ename}'")
        # Trap exits so terminate/2 runs on shutdown and can remove the
        # store projection (a stopped enforcer must stop answering).
        Process.flag(:trap_exit, true)
        Store.sync(ename, enforcer, :bulk)

        if opts == [] do
          {:ok, enforcer}
        else
          {:ok, enforcer, {:continue, {:wire, ename, opts}}}
        end
    end
  end

  def terminate(reason, _enforcer) when reason in [:normal, :shutdown] do
    Store.drop(self_name())
    :ok
  end

  def terminate({:shutdown, _}, _enforcer) do
    Store.drop(self_name())
    :ok
  end

  # On crashes, keep the projection: reads stay available from the last
  # consistent state until the supervisor restarts the enforcer, which
  # re-projects in init/1.
  def terminate(_reason, _enforcer), do: :ok

  def handle_continue({:wire, ename, opts}, enforcer) do
    enforcer =
      enforcer
      |> wire_adapter(opts[:adapter])
      |> wire_watcher(ename, opts[:watcher])
      |> wire_load(Keyword.get(opts, :load, opts[:adapter] != nil))

    {:noreply, commit(enforcer, nil, :bulk)}
  end

  def handle_call({:allow?, req}, _from, enforcer) do
    allowed = enforcer |> Enforcer.allow?(req)
    {:reply, allowed, enforcer}
  end

  def handle_call({:add_policy, {key, attrs}}, _from, enforcer) do
    case Enforcer.add_policy(enforcer, {key, attrs}) do
      {:error, reason} ->
        {:reply, {:error, reason}, enforcer}

      result ->
        event = %Event{op: :add_policy, ptype: key, rules: [attrs]}
        {:reply, :ok, result |> unwrap() |> commit(event, {:add, [{key, attrs}]})}
    end
  end

  def handle_call({:remove_policy, {key, attrs}}, _from, enforcer) do
    case Enforcer.remove_policy(enforcer, {key, attrs}) do
      {:error, reason} ->
        {:reply, {:error, reason}, enforcer}

      result ->
        event = %Event{op: :remove_policy, ptype: key, rules: [attrs]}
        {:reply, :ok, result |> unwrap() |> commit(event, {:remove, [{key, attrs}]})}
    end
  end

  def handle_call({:add_policies, key, attrs_list}, _from, enforcer) do
    rules = Enum.map(attrs_list, &{key, &1})

    case Enforcer.add_policies(enforcer, rules) do
      {:error, reason} ->
        {:reply, {:error, reason}, enforcer}

      new_enforcer ->
        event = %Event{op: :add_policy, ptype: key, rules: attrs_list}
        {:reply, :ok, commit(new_enforcer, event, {:add, rules})}
    end
  end

  def handle_call({:remove_policies, key, attrs_list}, _from, enforcer) do
    rules = Enum.map(attrs_list, &{key, &1})

    case Enforcer.remove_policies(enforcer, rules) do
      {:error, reason} ->
        {:reply, {:error, reason}, enforcer}

      new_enforcer ->
        event = %Event{op: :remove_policy, ptype: key, rules: attrs_list}
        {:reply, :ok, commit(new_enforcer, event, {:remove, rules})}
    end
  end

  def handle_call({:load_policies}, _from, enforcer) do
    case enforcer |> Enforcer.load_policies!() do
      {:error, reason} ->
        {:reply, {:error, reason}, enforcer}

      new_enforcer ->
        {:reply, :ok, new_enforcer |> refresh_revision() |> commit(nil, :bulk)}
    end
  end

  def handle_call({:load_policies, pfile}, _from, enforcer) do
    new_enforcer = enforcer |> Enforcer.load_policies!(pfile)
    {:reply, :ok, commit(new_enforcer, nil, :bulk)}
  end

  def handle_call({:load_filtered_policies, filter}, _from, enforcer) do
    new_enforcer = enforcer |> Enforcer.load_filtered_policies!(filter)
    {:reply, :ok, commit(new_enforcer, nil, :bulk)}
  end

  def handle_call({:list_policies, criteria}, _from, enforcer) do
    policies = enforcer |> Enforcer.list_policies(criteria)
    {:reply, policies, enforcer}
  end

  def handle_call({:save_policies}, _from, enforcer) do
    case enforcer |> Enforcer.save_policies() do
      {:error, reason} ->
        {:reply, {:error, reason}, enforcer}

      new_enforcer ->
        # A save rewrites all of storage; there is no incremental payload
        # peers could apply, so they are told to reload.
        {:reply, :ok, commit(new_enforcer, %Event{op: :full_reload}, :none)}
    end
  end

  def handle_call({:add_mapping_policy, mapping}, _from, enforcer) do
    case Enforcer.add_mapping_policy(enforcer, mapping) do
      {:error, reason} ->
        {:reply, {:error, reason}, enforcer}

      result ->
        {:reply, :ok,
         result |> unwrap() |> commit(mapping_event(:add_mapping_policy, mapping), :roles)}
    end
  end

  def handle_call({:load_mapping_policies}, _from, enforcer) do
    new_enforcer = enforcer |> Enforcer.load_mapping_policies!()
    {:reply, :ok, new_enforcer |> refresh_revision() |> commit(nil, :bulk)}
  end

  def handle_call({:load_mapping_policies, fname}, _from, enforcer) do
    new_enforcer = enforcer |> Enforcer.load_mapping_policies!(fname)
    {:reply, :ok, commit(new_enforcer, nil, :bulk)}
  end

  def handle_call({:remove_mapping_policy, mapping}, _from, enforcer) do
    case Enforcer.remove_mapping_policy(enforcer, mapping) do
      {:error, reason} ->
        {:reply, {:error, reason}, enforcer}

      result ->
        {:reply, :ok,
         result |> unwrap() |> commit(mapping_event(:remove_mapping_policy, mapping), :roles)}
    end
  end

  def handle_call({:remove_filtered_policy, key, idx, attrs}, _from, enforcer) do
    case Enforcer.remove_filtered_policy(enforcer, key, idx, attrs) do
      {:error, reason} ->
        {:reply, {:error, reason}, enforcer}

      new_enforcer ->
        event = %Event{
          op: :remove_filtered_policy,
          ptype: key,
          field_index: idx,
          field_values: attrs
        }

        {:reply, :ok, commit(new_enforcer, event, :bulk)}
    end
  end

  def handle_call({:reset_configuration, cfile}, _from, enforcer) do
    case Enforcer.init(cfile) do
      {:error, reason} ->
        {:reply, {:error, reason}, enforcer}

      {:ok, new_enforcer} ->
        {:reply, :ok, commit(new_enforcer, nil, :bulk)}
    end
  end

  def handle_call({:add_fun, {fun_name, fun}}, _from, enforcer) do
    new_enforcer = enforcer |> Enforcer.add_fun({fun_name, fun})
    {:reply, :ok, commit(new_enforcer, nil, :none)}
  end

  def handle_call({:set_persist_adapter, adapter}, _from, enforcer) do
    new_enforcer = Enforcer.set_persist_adapter(enforcer, adapter)
    {:reply, :ok, commit(new_enforcer, nil, :none)}
  end

  def handle_call({:set_watcher, watcher, instance_id}, _from, enforcer) do
    {:reply, :ok,
     commit(%{enforcer | watcher: watcher, watcher_instance_id: instance_id}, nil, :none)}
  end

  def handle_call({:apply_watcher_event, %Event{} = event}, _from, enforcer) do
    own_id = enforcer.watcher_instance_id

    cond do
      # our own event echoed back through the channel
      event.instance_id != nil and event.instance_id == own_id ->
        {:reply, :ok, enforcer}

      event.op == :full_reload ->
        reload_and_reply(enforcer, event.revision)

      # duplicate or out-of-order event we already covered
      stale_event?(event, enforcer) ->
        {:reply, :ok, enforcer}

      # at least one event between this one and our state got lost;
      # incremental apply would silently diverge, so reload instead
      gap_event?(event, enforcer) ->
        reload_and_reply(enforcer, event.revision)

      true ->
        new_enforcer =
          enforcer
          |> apply_incremental(event)
          |> put_revision(event.revision)

        {:reply, :ok, commit(new_enforcer, nil, change_hint(event))}
    end
  end

  def handle_call({:reload_policies}, _from, enforcer) do
    reload_and_reply(enforcer, nil)
  end

  def handle_call({:get_revision}, _from, enforcer) do
    {:reply, enforcer.revision, enforcer}
  end

  #
  # Helpers
  #

  # Startup wiring (handle_continue): adapter -> watcher -> load, so no
  # request is served before the initial load and no update published
  # during the load is missed.

  defp wire_adapter(enforcer, nil), do: enforcer
  defp wire_adapter(enforcer, adapter), do: Enforcer.set_persist_adapter(enforcer, adapter)

  defp wire_watcher(enforcer, _ename, nil), do: enforcer

  defp wire_watcher(enforcer, ename, {module, ref} = watcher) do
    # The watcher's callback is not installed yet, so it cannot be calling
    # into this process — these synchronous calls are safe here.
    instance_id = Watcher.instance_id(watcher)
    :ok = Watcher.set_update_callback(watcher, fn event -> apply_watcher_event(ename, event) end)

    # Subscribe-before-load: wait for the subscription so a mutation
    # committed by a peer during our initial load arrives as an (idempotent)
    # event instead of being missed.
    if function_exported?(module, :await_ready, 1) do
      module.await_ready(ref)
    end

    %{enforcer | watcher: watcher, watcher_instance_id: instance_id}
  end

  defp wire_load(enforcer, false), do: enforcer

  defp wire_load(enforcer, true) do
    case Enforcer.load_policies!(enforcer) do
      {:error, reason} ->
        raise "casbin: failed to load policies during enforcer wiring: #{inspect(reason)}"

      loaded ->
        loaded |> Enforcer.load_mapping_policies!() |> refresh_revision()
    end
  end

  # Some Enforcer functions return the struct bare, others wrapped in
  # {:ok, _}; normalize before committing.
  defp unwrap({:ok, %Enforcer{} = enforcer}), do: enforcer
  defp unwrap(%Enforcer{} = enforcer), do: enforcer

  # Above this many rules the restart-recovery mirror stores a slim
  # record instead of the full struct: copying tens of thousands of
  # policies into ETS on every mutation is O(n) per write, and at that
  # scale the persist adapter is the recovery source anyway.
  @full_mirror_limit 5_000

  # Single write path for every state change: publish the change to peers
  # (when a watcher is set and the change is replicable), project the new
  # state into Casbin.Store for the lock-free read path, and mirror the
  # struct into the ETS table used for restart recovery.
  defp commit(%Enforcer{} = enforcer, event, change) do
    enforcer = maybe_notify(enforcer, event)
    ename = self_name()
    Store.sync(ename, enforcer, change)
    :ets.insert(:enforcers_table, {ename, mirror(enforcer)})
    enforcer
  end

  defp mirror(%Enforcer{} = enforcer) do
    if MapSet.size(enforcer.policy_set) + MapSet.size(enforcer.mapping_policy_set) <=
         @full_mirror_limit do
      enforcer
    else
      # Strip everything reload_policies!/1 rebuilds from the adapter,
      # including the env role stubs (their closures capture the role
      # graphs, which would defeat the slimming).
      role_mapping_names = enforcer.model.role_mappings || []

      {:slim,
       %{
         enforcer
         | policies: [],
           policy_set: MapSet.new(),
           mapping_policies: [],
           mapping_policy_set: MapSet.new(),
           role_groups: %{},
           env: Map.drop(enforcer.env, role_mapping_names)
       }}
    end
  end

  # Maps a replicated event to the store-projection change hint.
  defp change_hint(%Event{op: :add_policy, ptype: key, rules: rules}),
    do: {:add, Enum.map(rules, &{key, &1})}

  defp change_hint(%Event{op: :remove_policy, ptype: key, rules: rules}),
    do: {:remove, Enum.map(rules, &{key, &1})}

  defp change_hint(%Event{op: op}) when op in [:add_mapping_policy, :remove_mapping_policy],
    do: :roles

  defp change_hint(%Event{}), do: :bulk

  defp maybe_notify(%Enforcer{watcher: nil} = enforcer, _event), do: enforcer
  defp maybe_notify(%Enforcer{} = enforcer, nil), do: enforcer

  defp maybe_notify(%Enforcer{watcher: watcher} = enforcer, %Event{} = event) do
    {revision, enforcer} = bump_revision(enforcer)

    event = %{
      event
      | instance_id: enforcer.watcher_instance_id,
        revision: revision,
        enforcer: self_name(),
        ts: System.system_time(:millisecond)
    }

    # The local mutation already succeeded and storage is the source of
    # truth; a failing publish must not fail the caller. Peers converge
    # through their reconciliation reload instead.
    try do
      case Watcher.notify(watcher, event) do
        :ok -> :ok
        {:error, reason} -> Logger.warning("casbin: watcher notify failed: #{inspect(reason)}")
      end
    rescue
      error -> Logger.warning("casbin: watcher notify raised: #{inspect(error)}")
    catch
      :exit, reason -> Logger.warning("casbin: watcher notify exited: #{inspect(reason)}")
    end

    enforcer
  end

  # Produces the next revision for a change made by this instance. Without
  # an Ecto adapter (or when the casbin_revision table is missing) events
  # carry no revision and receivers skip gap detection.
  defp bump_revision(%Enforcer{persist_adapter: %EctoAdapter{} = adapter} = enforcer) do
    case Revision.bump(EctoAdapter.get_repo(adapter), self_name()) do
      {:ok, revision} ->
        {revision, %{enforcer | revision: revision}}

      {:error, reason} ->
        Logger.warning("casbin: revision bump failed: #{inspect(reason)}")
        {nil, enforcer}
    end
  rescue
    error ->
      Logger.warning("casbin: revision bump raised: #{inspect(error)}")
      {nil, enforcer}
  end

  defp bump_revision(%Enforcer{} = enforcer), do: {nil, enforcer}

  # Aligns the in-memory revision with storage after a (re)load.
  defp refresh_revision(%Enforcer{persist_adapter: %EctoAdapter{} = adapter} = enforcer) do
    case Revision.current(EctoAdapter.get_repo(adapter), self_name()) do
      {:ok, revision} -> %{enforcer | revision: revision}
      {:error, _reason} -> enforcer
    end
  rescue
    _error -> enforcer
  end

  defp refresh_revision(%Enforcer{} = enforcer), do: enforcer

  defp put_revision(%Enforcer{} = enforcer, nil), do: enforcer
  defp put_revision(%Enforcer{} = enforcer, revision), do: %{enforcer | revision: revision}

  defp stale_event?(%Event{revision: revision}, %Enforcer{revision: own}),
    do: is_integer(revision) and own > 0 and revision <= own

  defp gap_event?(%Event{revision: revision}, %Enforcer{revision: own}),
    do: is_integer(revision) and own > 0 and revision > own + 1

  defp reload_and_reply(%Enforcer{} = enforcer, revision) do
    case Enforcer.reload_policies!(enforcer) do
      {:error, reason} ->
        Logger.warning("casbin: policy reload failed: #{inspect(reason)}")
        {:reply, {:error, reason}, enforcer}

      new_enforcer ->
        new_enforcer =
          case revision do
            nil -> refresh_revision(new_enforcer)
            revision -> put_revision(new_enforcer, revision)
          end

        {:reply, :ok, commit(new_enforcer, nil, :bulk)}
    end
  end

  defp apply_incremental(enforcer, %Event{op: :add_policy, ptype: key, rules: rules}) do
    Enum.reduce(rules, enforcer, fn attrs, e ->
      Enforcer.apply_added_policy(e, {key, attrs})
    end)
  end

  defp apply_incremental(enforcer, %Event{op: :remove_policy, ptype: key, rules: rules}) do
    Enum.reduce(rules, enforcer, fn attrs, e ->
      Enforcer.apply_removed_policy(e, {key, attrs})
    end)
  end

  defp apply_incremental(enforcer, %Event{
         op: :remove_filtered_policy,
         ptype: key,
         field_index: idx,
         field_values: values
       })
       when is_integer(idx) and is_list(values) do
    Enforcer.apply_removed_filtered_policy(enforcer, key, idx, values)
  end

  defp apply_incremental(enforcer, %Event{op: :add_mapping_policy, ptype: name, rules: rules}) do
    Enum.reduce(rules, enforcer, fn attrs, e ->
      Enforcer.apply_added_mapping_policy(e, List.to_tuple([name | attrs]))
    end)
  end

  defp apply_incremental(enforcer, %Event{op: :remove_mapping_policy, ptype: name, rules: rules}) do
    Enum.reduce(rules, enforcer, fn attrs, e ->
      Enforcer.apply_removed_mapping_policy(e, List.to_tuple([name | attrs]))
    end)
  end

  defp apply_incremental(enforcer, %Event{} = event) do
    Logger.debug("casbin: ignoring unappliable watcher event: #{inspect(event)}")
    enforcer
  end

  defp mapping_event(op, mapping) do
    [name | attrs] = Tuple.to_list(mapping)
    %Event{op: op, ptype: name, rules: [attrs]}
  end

  # Returns a tuple used to register and lookup an enforcer process
  # by name
  defp via_tuple(ename) do
    {:via, Registry, {Casbin.EnforcerRegistry, ename}}
  end

  # Returns the name of `self`.
  defp self_name do
    Registry.keys(Casbin.EnforcerRegistry, self()) |> List.first()
  end

  # Creates a new enforcer or lookups existing one in the ets table.
  defp create_new_or_lookup_enforcer(ename, cfile) do
    case :ets.lookup(:enforcers_table, ename) do
      [] ->
        case Enforcer.init(cfile) do
          {:error, reason} ->
            {:error, reason}

          {:ok, enforcer} ->
            :ets.insert(:enforcers_table, {ename, enforcer})
            {:ok, enforcer}
        end

      [{^ename, %Enforcer{} = enforcer}] ->
        {:ok, enforcer}

      [{^ename, {:slim, %Enforcer{} = slim}}] ->
        # Large policy set: the mirror holds only the configuration, the
        # policies themselves come back from the persist adapter.
        case Enforcer.reload_policies!(slim) do
          %Enforcer{} = recovered ->
            {:ok, recovered}

          {:error, reason} ->
            Logger.warning(
              "casbin: could not reload policies while recovering '#{ename}': " <>
                "#{inspect(reason)}; starting with the configuration only"
            )

            {:ok, slim}
        end
    end
  end
end
