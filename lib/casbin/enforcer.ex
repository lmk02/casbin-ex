defmodule Casbin.Enforcer do
  @moduledoc """
  TODO
  """

  defstruct model: nil,
            policies: [],
            policy_set: MapSet.new(),
            mapping_policies: [],
            mapping_policy_set: MapSet.new(),
            role_groups: [],
            env: %{},
            persist_adapter: nil,
            watcher: nil,
            watcher_instance_id: nil,
            revision: 0

  alias Casbin.Internal.PatternCache
  alias Casbin.Internal.RoleGroup
  alias Casbin.Model
  alias Casbin.Model.PolicyEffect
  alias Casbin.Persist.PersistAdapter
  alias Casbin.Persist.PersistAdapterBatch
  alias Casbin.Persist.ReadonlyFileAdapter

  require Logger

  @type mapping() ::
          {atom(), String.t(), String.t()}
          | {atom(), String.t(), String.t(), String.t()}

  @type t() :: %__MODULE__{
          model: Model.t(),
          policies: [Model.Policy.t()],
          policy_set: MapSet.t(Model.Policy.t()),
          mapping_policies: [mapping()],
          mapping_policy_set: MapSet.t(mapping()),
          role_groups: %{atom() => RoleGroup.t()},
          env: map(),
          persist_adapter: PersistAdapter.t(),
          watcher: Casbin.Watcher.t() | nil,
          watcher_instance_id: String.t() | nil,
          revision: non_neg_integer()
        }

  @doc """
  Loads and contructs a model from the given config file `cfile`.
  """
  @spec init(String.t(), PersistAdapter.t()) :: {:ok, t()} | {:error, String.t()}
  def init(cfile, adapter) when is_binary(cfile) do
    case init(cfile) do
      {:error, reason} ->
        {:error, reason}

      {:ok, module} ->
        module = set_persist_adapter(module, adapter)
        {:ok, module}
    end
  end

  @doc """
  Loads and contructs a model from the given config file `cfile`.
  """
  @spec init(String.t()) :: {:ok, t()} | {:error, String.t()}
  def init(cfile) when is_binary(cfile) do
    case Model.init(cfile) do
      {:error, reason} ->
        {:error, reason}

      {:ok, %Model{role_mappings: role_mappings} = model} ->
        role_groups =
          role_mappings
          |> Enum.map(fn m -> {m, RoleGroup.new(m)} end)

        # Merge role group functions with built-in functions, prioritizing built-ins
        # to prevent role mapping names from overriding core functionality
        env =
          role_groups
          |> Enum.map(fn {name, g} -> {name, RoleGroup.stub_2(g)} end)
          |> Map.new()
          |> Map.merge(init_env())

        {
          :ok,
          %__MODULE__{
            model: model,
            role_groups: role_groups |> Map.new(),
            persist_adapter: ReadonlyFileAdapter.new(),
            env: env
          }
        }
    end
  end

  @doc """
  Returns `true` if `request` is allowed, otherwise `false`.
  """
  @spec allow?(t(), [String.t()]) :: boolean()
  def allow?(
        %__MODULE__{model: %Model{effect: effect} = model, policies: policies, env: env},
        request
      )
      when is_list(request) do
    case Model.create_request(model, request) do
      {:error, _reason} ->
        Model.allow?(model, [])

      {:ok, req} ->
        # Short-circuit on the first decisive policy instead of matching
        # the full policy list; both supported effects allow this.
        case PolicyEffect.mode(effect) do
          :allow_override -> decisive_match?(model, policies, req, env, true)
          :deny_override -> not decisive_match?(model, policies, req, env, false)
        end
    end
  end

  # Scans until the first matched policy whose eft equals the decisive
  # kind (`allow?` == decisive_allow?) and returns whether one was found.
  defp decisive_match?(model, policies, req, env, decisive_allow?) do
    Enum.reduce_while(policies, false, fn pol, acc ->
      if Model.match?(model, req, pol, env) and Model.Policy.allow?(pol) == decisive_allow? do
        {:halt, true}
      else
        {:cont, acc}
      end
    end)
  end

  #
  # Policy management.
  #

  @doc """
  Adds a new policy rule with key given by `key` and a list of
  attribute values `attr_values` to the enforcer.
  """
  @spec add_policy(t(), {atom(), [String.t()]}) :: t() | {:error, String.t()}
  def add_policy(
        %__MODULE__{persist_adapter: adapter} = enforcer,
        {_key, _attrs} = rule
      ) do
    with {:ok, enforcer} <- load_policy(enforcer, rule),
         {:ok, adapter} <- PersistAdapter.add_policy(adapter, rule) do
      %{enforcer | persist_adapter: adapter}
    else
      {:error, reason} -> {:error, reason}
      true -> {:error, :already_existed}
    end
  end

  @doc """
  Adds a new policy rule with key given by `key` and a list of attribute
  values `attr_values` to the enforcer.
  """
  def add_policy!(%__MODULE__{} = enforcer, {key, attrs}) do
    case add_policy(enforcer, {key, attrs}) do
      {:error, reason} ->
        raise ArgumentError, message: reason

      enforcer ->
        enforcer
    end
  end

  @spec load_policy(t(), {atom(), [String.t()]}) :: t() | {:error, String.t()}
  defp load_policy(
         %__MODULE__{
           model: model,
           policies: policies,
           policy_set: policy_set,
           persist_adapter: adapter
         } = enforcer,
         {key, attrs}
       ) do
    with {:ok, policy} <- Model.create_policy(model, {key, attrs}),
         false <- MapSet.member?(policy_set, policy) do
      enforcer = %{
        enforcer
        | policies: [policy | policies],
          policy_set: MapSet.put(policy_set, policy),
          persist_adapter: adapter
      }

      {:ok, enforcer}
    else
      {:error, reason} -> {:error, reason}
      true -> {:error, :already_existed}
    end
  end

  defp load_policy!(%__MODULE__{} = enforcer, {key, attrs}) do
    case load_policy(enforcer, {key, attrs}) do
      {:error, reason} ->
        raise ArgumentError, message: reason

      {:ok, enforcer} ->
        enforcer
    end
  end

  @doc """
  Adds a batch of policy rules in one shot: one in-memory update and one
  batched adapter write (see `Casbin.Persist.PersistAdapterBatch`).

  Rules already present are skipped; invalid rules fail the whole call
  without changing anything.
  """
  @spec add_policies(t(), [{atom(), [String.t()]}]) :: t() | {:error, any()}
  def add_policies(%__MODULE__{} = enforcer, rules) when is_list(rules) do
    case validate_rules(enforcer, rules) do
      {:error, reason} ->
        {:error, reason}

      {:ok, policies} ->
        fresh =
          policies
          |> Enum.uniq()
          |> Enum.reject(fn {_rule, policy} -> MapSet.member?(enforcer.policy_set, policy) end)
          |> Enum.map(fn {rule, _policy} -> rule end)

        case PersistAdapterBatch.add_policies(enforcer.persist_adapter, fresh) do
          {:ok, adapter} ->
            fresh
            |> Enum.reduce(enforcer, &apply_added_policy(&2, &1))
            |> Map.put(:persist_adapter, adapter)

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  @doc """
  Removes a batch of policy rules in one shot; rules that are not present
  are ignored.
  """
  @spec remove_policies(t(), [{atom(), [String.t()]}]) :: t() | {:error, any()}
  def remove_policies(%__MODULE__{} = enforcer, rules) when is_list(rules) do
    present =
      rules
      |> Enum.uniq()
      |> Enum.filter(fn rule ->
        case Model.create_policy(enforcer.model, rule) do
          {:ok, policy} -> MapSet.member?(enforcer.policy_set, policy)
          {:error, _} -> false
        end
      end)

    case PersistAdapterBatch.remove_policies(enforcer.persist_adapter, present) do
      {:ok, adapter} ->
        present
        |> Enum.reduce(enforcer, &apply_removed_policy(&2, &1))
        |> Map.put(:persist_adapter, adapter)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp validate_rules(%__MODULE__{model: model}, rules) do
    Enum.reduce_while(rules, {:ok, []}, fn rule, {:ok, acc} ->
      case Model.create_policy(model, rule) do
        {:ok, policy} -> {:cont, {:ok, [{rule, policy} | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, pairs} -> {:ok, Enum.reverse(pairs)}
      error -> error
    end
  end

  @doc """
  Removes the policy rule or rules that match from the enforcer.
  """
  def remove_policy(
        %__MODULE__{model: model, policy_set: policy_set, persist_adapter: adapter} = enforcer,
        {key, attrs}
      ) do
    with {:ok, policy} <- Model.create_policy(model, {key, attrs}),
         true <- MapSet.member?(policy_set, policy),
         {:ok, _adapter} <- PersistAdapter.remove_policy(adapter, {key, attrs}) do
      drop_policy(enforcer, policy)
    else
      false -> {:error, :nonexistent}
      {:error, reason} -> {:error, reason}
    end
  end

  # Memory-only removal of an existing policy struct.
  defp drop_policy(%__MODULE__{policies: policies, policy_set: policy_set} = enforcer, policy) do
    %{
      enforcer
      | policies: Enum.reject(policies, fn p -> p == policy end),
        policy_set: MapSet.delete(policy_set, policy)
    }
  end

  @spec remove_policy!(any, any) :: t()
  def remove_policy!(%__MODULE__{} = enforcer, {key, attrs}) do
    case remove_policy(enforcer, {key, attrs}) do
      {:error, reason} ->
        raise ArgumentError, message: reason

      enforcer ->
        enforcer
    end
  end

  @doc """
  Removes policies with attributes that match the filter fields
  starting at the index.any()

    # Examples
        iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
        ...> {:ok, e} = Enforcer.init(cfile)
        ...> e = Enforcer.add_policy(e, {:p, ["admin", "blog_post", "write"]})
        ...> e = Enforcer.add_policy(e, {:p, ["reader", "blog_post", "read"]})
        ...> e = Enforcer.add_policy(e, {:p, ["admin", "blog_post", "delete"]})
        ...> e = Enforcer.remove_filtered_policy(e, :p, 0, ["admin"])
        ...> Enforcer.list_policies(e)
        [
          %Casbin.Model.Policy{
            key: :p,
            attrs: [sub: "reader", obj: "blog_post", act: "read", eft: "allow"]
          }
        ]


        iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
        ...> {:ok, e} = Enforcer.init(cfile)
        ...> e = Enforcer.add_policy(e, {:p, ["admin", "blog_post", "write"]})
        ...> e = Enforcer.add_policy(e, {:p, ["reader", "blog_post", "read"]})
        ...> e = Enforcer.add_policy(e, {:p, ["admin", "blog_post", "delete"]})
        ...> e = Enforcer.add_policy(e, {:p, ["reader", "comment", "read"]})
        ...> e = Enforcer.remove_filtered_policy(e, :p, 1, ["blog_post"])
        ...> Enforcer.list_policies(e)
        [
          %Casbin.Model.Policy{
            key: :p,
            attrs: [sub: "reader", obj: "comment", act: "read", eft: "allow"]
          }
        ]
  """
  @spec remove_filtered_policy(t(), atom(), integer(), keyword()) :: t() | {:error, any()}
  def remove_filtered_policy(
        %__MODULE__{persist_adapter: adapter} = enforcer,
        req_key,
        idx,
        req
      )
      when is_atom(req_key) and is_integer(idx) and is_list(req) do
    case PersistAdapter.remove_filtered_policy(adapter, req_key, idx, req) do
      {:ok, adapter} ->
        enforcer
        |> drop_filtered_policies(req_key, idx, req)
        |> Map.put(:persist_adapter, adapter)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Memory-only removal of the policies matching the positional filter.
  defp drop_filtered_policies(%__MODULE__{policies: policies} = enforcer, req_key, idx, req) do
    {removed, kept} =
      policies
      |> Enum.split_with(fn %{key: key, attrs: attrs} ->
        attr_values =
          attrs
          |> Enum.map(&elem(&1, 1))
          |> Enum.slice(idx, length(req))

        [key | attr_values] === [req_key | req]
      end)

    %{
      enforcer
      | policies: kept,
        policy_set: MapSet.difference(enforcer.policy_set, MapSet.new(removed))
    }
  end

  @spec remove_filtered_policy!(t(), atom(), integer(), keyword()) :: t()
  def remove_filtered_policy!(
        %__MODULE__{} = enforcer,
        req_key,
        idx,
        req
      )
      when is_atom(req_key) and is_integer(idx) and is_list(req) do
    case remove_filtered_policy(enforcer, req_key, idx, req) do
      {:error, reason} ->
        raise ArgumentError, message: reason

      enforcer ->
        enforcer
    end
  end

  @doc """
  Sets the provided adapter to manage persisting rules in storage.
  """
  def set_persist_adapter(%__MODULE__{} = enforcer, adapter) do
    %{enforcer | persist_adapter: adapter}
  end

  @doc """
  Loads policy rules from external file given by the name `pfile` and
  adds them to the enforcer.

  A valid policy file should be a `*.csv` file, in which each line must
  have the following format:

    `pkey, attr1, attr2, attr3`

  in which `pkey` is the key of the policy rule, this key must match the
  policy definition in the enforcer. `attr1`, `attr2`, ... are the
  value of attributes specified in the policy definition.

  ## Examples

      iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
      ...> pfile = "../../test/data/acl.csv" |> Path.expand(__DIR__)
      ...> {:ok, e} = Enforcer.init(cfile)
      ...> e = e |> Enforcer.load_policies!(pfile)
      ...> %Enforcer{policies: policies} = e
      ...> policies
      [
      %Casbin.Model.Policy{
        attrs: [sub: "peter", obj: "blog_post", act: "read", eft: "allow"],
        key: :p
      },
      %Casbin.Model.Policy{
        attrs: [sub: "peter", obj: "blog_post", act: "modify", eft: "allow"],
        key: :p
      },
      %Casbin.Model.Policy{
        attrs: [sub: "peter", obj: "blog_post", act: "create", eft: "allow"],
        key: :p
      },
      %Casbin.Model.Policy{
        attrs: [sub: "bob", obj: "blog_post", act: "read", eft: "allow"],
        key: :p
      },
      %Casbin.Model.Policy{
        attrs: [sub: "alice", obj: "blog_post", act: "read", eft: "allow"],
        key: :p
      },
      %Casbin.Model.Policy{
        attrs: [sub: "alice", obj: "blog_post", act: "modify", eft: "allow"],
        key: :p
      },
      %Casbin.Model.Policy{
        attrs: [sub: "alice", obj: "blog_post", act: "delete", eft: "allow"],
        key: :p
      },
      %Casbin.Model.Policy{
        attrs: [sub: "alice", obj: "blog_post", act: "create", eft: "allow"],
        key: :p
      }
      ]
  """

  @spec load_policies!(t()) :: t() | {:error, any()}
  def load_policies!(%__MODULE__{persist_adapter: nil}) do
    {:error, "No adapter set and no policy file provided"}
  end

  @spec load_policies!(t()) :: t() | {:error, any()}
  def load_policies!(%__MODULE__{model: m, persist_adapter: adapter} = enforcer) do
    case PersistAdapter.load_policies(adapter) do
      {:ok, policies} ->
        policies
        |> Enum.map(fn [key | attrs] -> [String.to_atom(key) | attrs] end)
        |> Enum.filter(fn [key | _] -> Model.has_policy_key?(m, key) end)
        |> Enum.map(fn [key | attrs] -> {key, attrs} end)
        |> Enum.reduce(enforcer, &load_policy!(&2, &1))
    end
  end

  @spec load_policies!(t(), String.t()) :: t()
  def load_policies!(%__MODULE__{model: m} = enforcer, pfile)
      when is_binary(pfile) do
    adapter = ReadonlyFileAdapter.new(pfile)
    enforcer = %{enforcer | persist_adapter: adapter}

    case PersistAdapter.load_policies(adapter) do
      {:ok, policies} ->
        policies
        |> Enum.map(fn [key | attrs] -> [String.to_atom(key) | attrs] end)
        |> Enum.filter(fn [key | _] -> Model.has_policy_key?(m, key) end)
        |> Enum.map(fn [key | attrs] -> {key, attrs} end)
        |> Enum.reduce(enforcer, &load_policy!(&2, &1))
    end
  end

  @doc """
  Loads policies from the persist adapter using the given filter.
  Only matching policies are loaded into the enforcer.

  The filter is a map where keys can be `:ptype`, `:v0`, `:v1`, `:v2`, `:v3`, `:v4`, `:v5`, or `:v6`.
  Values can be either a single string or a list of strings for matching multiple values.

  ## Examples

      # Load only policies for a specific domain
      enforcer = Enforcer.load_filtered_policies!(enforcer, %{v3: "org:abc"})

      # Load policies with multiple criteria
      enforcer = Enforcer.load_filtered_policies!(enforcer, %{ptype: "p", v3: ["org:tenant_1", "org:tenant_2"]})
  """
  @spec load_filtered_policies!(t(), map()) :: t()
  def load_filtered_policies!(
        %__MODULE__{model: m, persist_adapter: adapter} = enforcer,
        filter
      )
      when is_map(filter) do
    case PersistAdapter.load_filtered_policy(adapter, filter) do
      {:ok, policies} ->
        policies
        |> Enum.map(fn [key | attrs] -> [String.to_atom(key) | attrs] end)
        |> Enum.filter(fn [key | _] -> Model.has_policy_key?(m, key) end)
        |> Enum.map(fn [key | attrs] -> {key, attrs} end)
        |> Enum.reduce(enforcer, &load_policy!(&2, &1))

      {:error, reason} ->
        raise ArgumentError, message: reason
    end
  end

  @doc """
  Returns a list of policies in the given enforcer that match the
  given criteria.

  For example, in order to get all policy rules with the key `:p`
  and the `act` attribute is `"read"`, you can call `list_policies/2`
  function with second argument:

  `%{key: :p, act: "read"}`

  By passing in an empty map or an empty list to the second argument
  of the function `list_policies/2`, you'll effectively get all policy
  rules in the enforcer (without filtered).

  ## Examples

      iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
      ...> pfile = "../../test/data/acl.csv" |> Path.expand(__DIR__)
      ...> {:ok, e} = Enforcer.init(cfile)
      ...> e = e |> Enforcer.load_policies!(pfile)
      ...> e |> Enforcer.list_policies(%{sub: "peter"})
      [
      %Casbin.Model.Policy{
        attrs: [sub: "peter", obj: "blog_post", act: "read", eft: "allow"],
        key: :p
      },
      %Casbin.Model.Policy{
        attrs: [sub: "peter", obj: "blog_post", act: "modify", eft: "allow"],
        key: :p
      },
      %Casbin.Model.Policy{
        attrs: [sub: "peter", obj: "blog_post", act: "create", eft: "allow"],
        key: :p
      }
      ]
  """
  @spec list_policies(t(), map() | keyword()) :: [Model.Policy.t()]
  def list_policies(
        %__MODULE__{policies: policies},
        criteria
      )
      when is_map(criteria) or is_list(criteria) do
    policies
    |> Enum.filter(fn %{key: key, attrs: attrs} ->
      list = [{:key, key} | attrs]
      criteria |> Enum.all?(fn c -> c in list end)
    end)
  end

  def list_policies(%__MODULE__{policies: policies}), do: policies

  @doc """
  Returns a list of policy rules in the given enforcer that match the
  given `request`.
  """
  @spec list_matched_policies(t(), [String.t()]) :: [Model.Policy.t()]
  def list_matched_policies(
        %__MODULE__{model: model, policies: policies, env: env},
        request
      )
      when is_list(request) do
    case Model.create_request(model, request) do
      {:error, _reason} ->
        []

      {:ok, req} ->
        policies
        |> Enum.filter(fn pol -> Model.match?(model, req, pol, env) end)
    end
  end

  #
  # RBAC role management
  #

  @spec load_mapping_policy(t(), {atom(), String.t(), String.t()}) ::
          t() | {:error, String.t()}
  defp load_mapping_policy(
         %__MODULE__{
           mapping_policies: mappings,
           role_groups: groups,
           env: env,
           persist_adapter: adapter
         } = enforcer,
         {mapping_name, role1, role2} = mapping
       )
       when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) do
    with group when not is_nil(group) <- Map.get(groups, mapping_name),
         false <- MapSet.member?(enforcer.mapping_policy_set, mapping),
         group <- RoleGroup.add_inheritance(group, {role1, role2}) do
      new_enforcer = %{
        enforcer
        | role_groups: %{groups | mapping_name => group},
          mapping_policies: [mapping | mappings],
          mapping_policy_set: MapSet.put(enforcer.mapping_policy_set, mapping),
          persist_adapter: adapter,
          env: %{env | mapping_name => RoleGroup.stub_2(group)}
      }

      {:ok, new_enforcer}
    else
      nil ->
        {:error, "mapping name not found: `#{mapping_name}`"}

      true ->
        {:error, :already_existed}
    end
  end

  @spec load_mapping_policy(t(), {atom(), String.t(), String.t(), String.t()}) ::
          t() | {:error, String.t()}
  defp load_mapping_policy(
         %__MODULE__{
           mapping_policies: mappings,
           role_groups: groups,
           env: env,
           persist_adapter: adapter
         } = enforcer,
         {mapping_name, role1, role2, dom} = mapping
       )
       when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) and is_binary(dom) do
    with group when not is_nil(group) <- Map.get(groups, mapping_name),
         false <- MapSet.member?(enforcer.mapping_policy_set, mapping),
         group <- RoleGroup.add_inheritance(group, {{role1, dom}, {role2, dom}}) do
      new_enforcer = %{
        enforcer
        | role_groups: %{groups | mapping_name => group},
          mapping_policies: [mapping | mappings],
          mapping_policy_set: MapSet.put(enforcer.mapping_policy_set, mapping),
          persist_adapter: adapter,
          env: %{env | mapping_name => RoleGroup.stub_3(group)}
      }

      {:ok, new_enforcer}
    else
      nil ->
        {:error, "mapping name not found: `#{mapping_name}`"}

      true ->
        {:error, :already_existed}
    end
  end

  defp load_mapping_policy!(
         %__MODULE__{} = enforcer,
         {mapping_name, role1, role2}
       )
       when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) do
    case load_mapping_policy(enforcer, {mapping_name, role1, role2}) do
      {:error, :already_existed} ->
        enforcer

      {:error, reason} ->
        raise ArgumentError, message: reason

      {:ok, enforcer} ->
        enforcer
    end
  end

  defp load_mapping_policy!(
         %__MODULE__{} = enforcer,
         {mapping_name, role1, role2, dom}
       )
       when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) and is_binary(dom) do
    case load_mapping_policy(enforcer, {mapping_name, role1, role2, dom}) do
      {:error, :already_existed} ->
        enforcer

      {:error, reason} ->
        raise ArgumentError, message: reason

      {:ok, enforcer} ->
        enforcer
    end
  end

  @doc """
  Makes `role1` inherit from (or has role ) `role2`. The `mapping_name`
  should be one of the names given in the model configuration file under
  the `role_definition` section. For example if your role definition look
  like this:

    [role_definition]
    g = _, _

  then `mapping_name` should be the atom `:g`.

  ## Examples

      iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
      ...> {:ok, e} = Enforcer.init(cfile)
      ...> e = e |> Enforcer.add_mapping_policy({:g, "bob", "admin"})
      ...> %Enforcer{env: %{g: g}} = e
      ...> false = g.("admin", "bob")
      ...> g.("bob", "admin")
      true

      iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
      ...> {:ok, e} = Enforcer.init(cfile)
      ...> e = e |> Enforcer.add_mapping_policy({:g, "bob", "admin"})
      ...> e = e |> Enforcer.add_mapping_policy({:g, "admin", "author"})
      ...> %Enforcer{env: %{g: g}} = e
      ...> g.("bob", "author")
      true

      iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
      ...> {:ok, e} = Enforcer.init(cfile)
      ...> invalid_mapping = {:g2, "bob", "admin"}
      ...> {:error, msg} = e |> Enforcer.add_mapping_policy(invalid_mapping)
      ...> msg
      "mapping name not found: `g2`"

      iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
      ...> {:ok, e} = Enforcer.init(cfile)
      ...> e = e |> Enforcer.add_mapping_policy({:g, "bob", "admin"})
      ...> e |> Enforcer.add_mapping_policy({:g, "bob", "admin"})
      {:error, :already_existed}
  """
  @spec add_mapping_policy(t(), {atom(), String.t(), String.t()}) ::
          t() | {:error, String.t()}
  def add_mapping_policy(
        %__MODULE__{persist_adapter: adapter} = enforcer,
        {mapping_name, role1, role2} = mapping
      )
      when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) do
    with {:ok, new_enforcer} <- load_mapping_policy(enforcer, mapping),
         {:ok, adapter} <- PersistAdapter.add_policy(adapter, {mapping_name, [role1, role2]}) do
      %{new_enforcer | persist_adapter: adapter}
    else
      {:error, reason} ->
        {:error, reason}
    end
  end

  def add_mapping_policy(
        %__MODULE__{persist_adapter: adapter} = enforcer,
        {mapping_name, role1, role2, dom} = mapping
      )
      when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) and is_binary(dom) do
    with {:ok, new_enforcer} <- load_mapping_policy(enforcer, mapping),
         {:ok, adapter} <- PersistAdapter.add_policy(adapter, {mapping_name, [role1, role2, dom]}) do
      %{new_enforcer | persist_adapter: adapter}
    else
      {:error, reason} ->
        {:error, reason}
    end
  end

  def add_mapping_policy!(
        %__MODULE__{} = enforcer,
        {mapping_name, role1, role2}
      )
      when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) do
    case add_mapping_policy(enforcer, {mapping_name, role1, role2}) do
      {:error, reason} ->
        raise ArgumentError, message: reason

      enforcer ->
        enforcer
    end
  end

  def add_mapping_policy!(
        %__MODULE__{} = enforcer,
        {mapping_name, role1, role2, dom}
      )
      when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) and is_binary(dom) do
    case add_mapping_policy(enforcer, {mapping_name, role1, role2, dom}) do
      {:error, reason} ->
        raise ArgumentError, message: reason

      enforcer ->
        enforcer
    end
  end

  @doc """
  Loads mapping policies from the persist adapter and adds them to the enforcer.
  """
  def load_mapping_policies!(%__MODULE__{model: m, persist_adapter: adapter} = enforcer) do
    case PersistAdapter.load_policies(adapter) do
      {:ok, policies} ->
        policies
        |> Enum.map(fn [key | attrs] -> [String.to_atom(key) | attrs] end)
        |> Enum.filter(fn [key | _] -> Model.has_role_mapping?(m, key) end)
        |> Enum.map(fn
          [name, r1, r2] -> {name, r1, r2}
          [name, r1, r2, d] -> {name, r1, r2, d}
        end)
        |> Enum.reduce(enforcer, &load_mapping_policy!(&2, &1))
    end
  end

  @doc """
  Loads mapping policies from a csv file and adds them to the enforcer.

  A valid mapping policies file must be a `*.csv` file and each line of
  that file should have the following format:

    `mapping_name, role1, role2`

  where `mapping_name` is one of the names given in the config file under
  the role definition section.

  Note that you don't have to have a separate mapping policies file, instead
  you could just put all of your mapping policies inside your policy rules
  file.
  """
  def load_mapping_policies!(%__MODULE__{model: m} = enforcer, fname)
      when is_binary(fname) do
    fname
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.map(&String.split(&1, ~r{,\s*}))
    |> Enum.map(fn [key | attrs] -> [String.to_atom(key) | attrs] end)
    |> Enum.filter(fn [key | _] -> Model.has_role_mapping?(m, key) end)
    |> Enum.map(fn
      [name, r1, r2] -> {name, r1, r2}
      [name, r1, r2, d] -> {name, r1, r2, d}
    end)
    |> Enum.reduce(enforcer, &load_mapping_policy!(&2, &1))
  end

  @doc """
  Removes the connection of the role to the permission and its corresponding
  mapping policy from storage.
  """
  @spec remove_mapping_policy(t(), {atom(), String.t(), String.t()}) :: t() | {:error, String.t()}
  def remove_mapping_policy(
        %__MODULE__{role_groups: groups, persist_adapter: adapter} = enforcer,
        {mapping_name, role1, role2} = mapping
      )
      when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) do
    with group when not is_nil(group) <- Map.get(groups, mapping_name),
         {:ok, adapter} <- PersistAdapter.remove_policy(adapter, {mapping_name, [role1, role2]}) do
      %{drop_mapping_policy(enforcer, mapping) | persist_adapter: adapter}
    else
      nil ->
        {:error, "mapping name not found: `#{mapping_name}`"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec remove_mapping_policy(t(), {atom(), String.t(), String.t(), String.t()}) ::
          t() | {:error, String.t()}
  def remove_mapping_policy(
        %__MODULE__{role_groups: groups, persist_adapter: adapter} = enforcer,
        {mapping_name, role1, role2, dom} = mapping
      )
      when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) and is_binary(dom) do
    with group when not is_nil(group) <- Map.get(groups, mapping_name),
         {:ok, adapter} <-
           PersistAdapter.remove_policy(adapter, {mapping_name, [role1, role2, dom]}) do
      %{drop_mapping_policy(enforcer, mapping) | persist_adapter: adapter}
    else
      nil ->
        {:error, "mapping name not found: `#{mapping_name}`"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Memory-only removal of a mapping policy: updates the role graph, the
  # mapping lists and the matcher env stub. The mapping name must exist.
  defp drop_mapping_policy(
         %__MODULE__{role_groups: groups, env: env} = enforcer,
         {mapping_name, role1, role2} = mapping
       ) do
    group =
      groups
      |> Map.fetch!(mapping_name)
      |> RoleGroup.remove_inheritance({role1, role2})

    %{
      enforcer
      | role_groups: %{groups | mapping_name => group},
        mapping_policies: Enum.reject(enforcer.mapping_policies, fn m -> m == mapping end),
        mapping_policy_set: MapSet.delete(enforcer.mapping_policy_set, mapping),
        env: %{env | mapping_name => RoleGroup.stub_2(group)}
    }
  end

  defp drop_mapping_policy(
         %__MODULE__{role_groups: groups, env: env} = enforcer,
         {mapping_name, role1, role2, dom} = mapping
       ) do
    group =
      groups
      |> Map.fetch!(mapping_name)
      |> RoleGroup.remove_inheritance({{role1, dom}, {role2, dom}})

    %{
      enforcer
      | role_groups: %{groups | mapping_name => group},
        mapping_policies: Enum.reject(enforcer.mapping_policies, fn m -> m == mapping end),
        mapping_policy_set: MapSet.delete(enforcer.mapping_policy_set, mapping),
        env: %{env | mapping_name => RoleGroup.stub_3(group)}
    }
  end

  def remove_mapping_policy!(
        %__MODULE__{} = enforcer,
        {mapping_name, role1, role2}
      )
      when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) do
    case remove_mapping_policy(enforcer, {mapping_name, role1, role2}) do
      {:error, reason} ->
        raise ArgumentError, message: reason

      enforcer ->
        enforcer
    end
  end

  def remove_mapping_policy!(
        %__MODULE__{} = enforcer,
        {mapping_name, role1, role2, dom}
      )
      when is_atom(mapping_name) and is_binary(role1) and is_binary(role2) and is_binary(dom) do
    case remove_mapping_policy(enforcer, {mapping_name, role1, role2, dom}) do
      {:error, reason} ->
        raise ArgumentError, message: reason

      enforcer ->
        enforcer
    end
  end

  @doc """
  Lists mapping policies and can take a filter that matches any position
  or displaced filter that matches positionally

  ## Examples

      iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
      ...> {:ok, e} = Enforcer.init(cfile)
      ...> e = e |> Enforcer.add_mapping_policy({:g, "author", "reader"})
      ...> e = e |> Enforcer.add_mapping_policy({:g, "admin", "author"})
      ...> e = e |> Enforcer.add_mapping_policy({:g, "bob", "admin"})
      ...> e = e |> Enforcer.add_mapping_policy({:g, "alice", "author"})
      ...> Enforcer.list_mapping_policies(e, ["author"])
      [
        {:g, "alice", "author"},
        {:g, "admin", "author"},
        {:g, "author", "reader"}
      ]

      iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
      ...> {:ok, e} = Enforcer.init(cfile)
      ...> e = e |> Enforcer.add_mapping_policy({:g, "author", "reader"})
      ...> e = e |> Enforcer.add_mapping_policy({:g, "admin", "author"})
      ...> e = e |> Enforcer.add_mapping_policy({:g, "bob", "admin"})
      ...> e = e |> Enforcer.add_mapping_policy({:g, "alice", "author"})
      ...> Enforcer.list_mapping_policies(e, 2, ["author"])
      [
        {:g, "alice", "author"},
        {:g, "admin", "author"}
      ]

      iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
      ...> {:ok, e} = Enforcer.init(cfile)
      ...> e = e |> Enforcer.add_mapping_policy({:g, "author", "reader"})
      ...> e = e |> Enforcer.add_mapping_policy({:g, "admin", "author"})
      ...> e = e |> Enforcer.add_mapping_policy({:g, "bob", "admin"})
      ...> e = e |> Enforcer.add_mapping_policy({:g, "alice", "author"})
      ...> Enforcer.list_mapping_policies(e, 1, ["admin", "author"])
      [
        {:g, "admin", "author"}
      ]
  """
  @spec list_mapping_policies(t(), integer(), keyword()) :: [mapping()]
  def list_mapping_policies(
        %__MODULE__{mapping_policies: mapping_policies},
        idx,
        criteria
      )
      when is_list(criteria) and is_integer(idx) do
    mapping_policies
    |> Enum.filter(fn mapping ->
      Tuple.to_list(mapping)
      |> Enum.slice(idx, length(criteria))
      |> Kernel.==(criteria)
    end)
  end

  @spec list_mapping_policies(Casbin.Enforcer.t(), maybe_improper_list) :: [mapping()]
  def list_mapping_policies(
        %__MODULE__{mapping_policies: mapping_policies},
        criteria
      )
      when is_list(criteria) do
    mapping_policies
    |> Enum.filter(fn mapping ->
      list = Tuple.to_list(mapping)
      criteria |> Enum.all?(fn c -> c in list end)
    end)
  end

  @spec list_mapping_policies(Casbin.Enforcer.t()) :: [mapping()]
  def list_mapping_policies(%__MODULE__{mapping_policies: mapping_policies}), do: mapping_policies

  @doc """
  Saves the updated list of policies using the configured PersistAdapter. This function
  is useful for adapters that don't do incremental add/removes for policies or for loading
  policies from one source and saving to another after changing adapters.
  """
  def save_policies(
        %__MODULE__{
          persist_adapter: adapter,
          policies: policies,
          mapping_policies: mapping_policies
        } = enforcer
      ) do
    policies =
      mapping_policies
      |> Enum.map(&Tuple.to_list(&1))
      |> Enum.map(fn [key | attrs] -> %{key: key, attrs: attrs} end)
      |> Enum.concat(policies)

    case PersistAdapter.save_policies(adapter, policies) do
      {:error, errors} -> {:error, errors}
      {:ok, adapter} -> %{enforcer | persist_adapter: adapter}
      adapter -> %{enforcer | persist_adapter: adapter}
    end
  end

  def save_policies!(%__MODULE__{} = enforcer) do
    case save_policies(enforcer) do
      {:error, _} ->
        raise RuntimeError, message: "save failed"

      enforcer ->
        enforcer
    end
  end

  #
  # Replication support.
  #
  # The `apply_*` functions mutate only the in-memory state. They exist for
  # multi-instance deployments where another instance already persisted a
  # change and broadcast it (see `Casbin.Watcher`); the receiving instance
  # must apply the change without writing it to storage again. They are
  # idempotent: applying an already-present add or an already-gone remove
  # leaves the enforcer unchanged instead of returning an error.
  #

  @doc """
  Adds a policy rule to the in-memory state only, without persisting it.

  No-op if the rule is already present.
  """
  @spec apply_added_policy(t(), {atom(), [String.t()]}) :: t()
  def apply_added_policy(%__MODULE__{} = enforcer, {_key, _attrs} = rule) do
    case load_policy(enforcer, rule) do
      {:ok, enforcer} ->
        enforcer

      {:error, :already_existed} ->
        enforcer

      {:error, reason} ->
        Logger.debug("casbin: ignoring replicated policy #{inspect(rule)}: #{inspect(reason)}")
        enforcer
    end
  end

  @doc """
  Removes a policy rule from the in-memory state only, without touching
  the persist adapter.

  No-op if the rule is not present.
  """
  @spec apply_removed_policy(t(), {atom(), [String.t()]}) :: t()
  def apply_removed_policy(
        %__MODULE__{model: model, policy_set: policy_set} = enforcer,
        {_key, _attrs} = rule
      ) do
    with {:ok, policy} <- Model.create_policy(model, rule),
         true <- MapSet.member?(policy_set, policy) do
      drop_policy(enforcer, policy)
    else
      _ -> enforcer
    end
  end

  @doc """
  Removes the policies matching the positional filter from the in-memory
  state only, without touching the persist adapter.
  """
  @spec apply_removed_filtered_policy(t(), atom(), integer(), [String.t()]) :: t()
  def apply_removed_filtered_policy(%__MODULE__{} = enforcer, req_key, idx, req)
      when is_atom(req_key) and is_integer(idx) and is_list(req) do
    drop_filtered_policies(enforcer, req_key, idx, req)
  end

  @doc """
  Adds a mapping (role inheritance) policy to the in-memory state only,
  without persisting it.

  No-op if the mapping is already present or its mapping name is unknown.
  """
  @spec apply_added_mapping_policy(t(), mapping()) :: t()
  def apply_added_mapping_policy(%__MODULE__{} = enforcer, mapping) when is_tuple(mapping) do
    case load_mapping_policy(enforcer, mapping) do
      {:ok, enforcer} ->
        enforcer

      {:error, :already_existed} ->
        enforcer

      {:error, reason} ->
        Logger.debug(
          "casbin: ignoring replicated mapping #{inspect(mapping)}: #{inspect(reason)}"
        )

        enforcer
    end
  end

  @doc """
  Removes a mapping (role inheritance) policy from the in-memory state
  only, without touching the persist adapter.

  No-op if the mapping is not present.
  """
  @spec apply_removed_mapping_policy(t(), mapping()) :: t()
  def apply_removed_mapping_policy(%__MODULE__{role_groups: groups} = enforcer, mapping)
      when is_tuple(mapping) do
    if Map.has_key?(groups, elem(mapping, 0)) and
         MapSet.member?(enforcer.mapping_policy_set, mapping) do
      drop_mapping_policy(enforcer, mapping)
    else
      enforcer
    end
  end

  @doc """
  Discards all in-memory policies and mapping policies and reloads both
  from the persist adapter.

  Unlike re-initializing the enforcer, this preserves the configured
  persist adapter and any user-defined functions added with `add_fun/2`.
  Use this to re-synchronize with storage after missed updates.
  """
  @spec reload_policies!(t()) :: t() | {:error, any()}
  def reload_policies!(%__MODULE__{model: model, env: env} = enforcer) do
    %Model{role_mappings: role_mappings} = model
    role_groups = role_mappings |> Enum.map(fn m -> {m, RoleGroup.new(m)} end) |> Map.new()
    builtins = init_env()

    # Reset the role stubs in env to the fresh (empty) groups while leaving
    # built-ins and user-added functions untouched; init/1 gives built-ins
    # priority over role stub names, so do the same here.
    role_stubs =
      for {name, group} <- role_groups, not Map.has_key?(builtins, name), into: %{} do
        {name, RoleGroup.stub_2(group)}
      end

    reset = %{
      enforcer
      | policies: [],
        policy_set: MapSet.new(),
        mapping_policies: [],
        mapping_policy_set: MapSet.new(),
        role_groups: role_groups,
        env: Map.merge(env, role_stubs)
    }

    # Fold through apply_added_policy/2 instead of load_policies!/1 so
    # duplicate rows in storage (possible without a unique index) are
    # skipped rather than raising mid-reload.
    case PersistAdapter.load_policies(reset.persist_adapter) do
      {:ok, raw_policies} ->
        raw_policies
        |> Enum.map(fn [key | attrs] -> [String.to_atom(key) | attrs] end)
        |> Enum.filter(fn [key | _] -> Model.has_policy_key?(model, key) end)
        |> Enum.reduce(reset, fn [key | attrs], e -> apply_added_policy(e, {key, attrs}) end)
        |> load_mapping_policies!()

      {:error, reason} ->
        {:error, reason}
    end
  end

  #
  # User defined function.
  #

  @doc """
  Adds a user-defined function to the enforcer.

  Like built-in function `regex_match?/2`, you can define your own
  function and add it to the enforcer to use in your matcher expression.
  Note that the `fun_name` must match the name used in the matcher
  expression.

  ## Examples

      iex> cfile = "../../test/data/rbac.conf" |> Path.expand(__DIR__)
      ...> {:ok, e} = Enforcer.init(cfile)
      ...> my_fun = fn x, y -> x + y end
      ...> e = e |> Enforcer.add_fun({:my_fun, my_fun})
      ...> %Enforcer{env: %{my_fun: f}} = e
      ...> f.(1, 2)
      3
  """
  @spec add_fun(t(), {atom(), function()}) :: t()
  def add_fun(%__MODULE__{env: env} = enforcer, {fun_name, fun})
      when is_atom(fun_name) and is_function(fun) do
    %{enforcer | env: Map.put(env, fun_name, fun)}
  end

  #
  # Build in stubs function
  #

  @doc """
  Returns `true` if the given string `str` matches the pattern
  string `^pattern$`.

  Returns `false` otherwise.

  ## Examples

      iex> Enforcer.regex_match?("/alice_data/foo", "/alice_data/.*")
      true
  """
  @spec regex_match?(String.t(), String.t()) :: boolean()
  def regex_match?(str, pattern) do
    compiled =
      PatternCache.fetch(:regex_match, pattern, fn ->
        case Regex.compile("^#{pattern}$") do
          {:ok, r} -> {:ok, r}
          {:error, _} -> :error
        end
      end)

    case compiled do
      {:ok, r} -> Regex.match?(r, str)
      :error -> false
    end
  end

  @doc """
  Returns `true` if `key1` matches the pattern of `key2`.

  `key2` can contain a `*` wildcard.

  ## Examples

      iex> Enforcer.key_match?("/foo/bar", "/foo/*")
      true
      iex> Enforcer.key_match?("/foo/bar", "/foo*")
      true
      iex> Enforcer.key_match?("/foo", "/foo")
      true
  """
  @spec key_match?(String.t(), String.t()) :: boolean()
  def key_match?(key1, key2) do
    case String.split(key2, "*", parts: 2) do
      [prefix, _] ->
        if String.length(key1) >= String.length(prefix) do
          String.starts_with?(key1, prefix)
        else
          key1 == prefix
        end

      [_] ->
        key1 == key2
    end
  end

  @doc """
  Returns the matched part of `key1` based on pattern `key2`.

  For example, `/foo/bar/foo` matches `/foo/*` and returns `bar/foo`.

  ## Examples

      iex> Enforcer.key_get("/foo/bar", "/foo/*")
      "bar"
      iex> Enforcer.key_get("/foo/bar", "/foo*")
      "/bar"
  """
  @spec key_get(String.t(), String.t()) :: String.t()
  def key_get(key1, key2) do
    i = :binary.match(key2, "*")

    case i do
      :nomatch ->
        ""

      {pos, _} ->
        if String.length(key1) > pos do
          prefix = String.slice(key2, 0, pos)

          if String.starts_with?(key1, prefix) do
            String.slice(key1, pos, String.length(key1) - pos)
          else
            ""
          end
        else
          ""
        end
    end
  end

  @doc """
  Returns `true` if `key1` matches the pattern of `key2`.

  Returns `false` otherwise.

  `key_match2?/2` can handle three types of path / patterns :

    URL path like `/alice_data/resource1`.
    `:` pattern like `/alice_data/:resource`.
    `*` pattern like `/alice_data/*`.

  ## Parameters

  - `key1` should be a URL path.
  - `key2` can be a URL path, a `:` pattern or a `*` pattern.

  ## Examples

      iex> Enforcer.key_match2?("alice_data/resource1", "alice_data/*")
      true
      iex> Enforcer.key_match2?("alice_data/resource1", "alice_data/:resource")
      true
  """
  @spec key_match2?(String.t(), String.t()) :: boolean()
  def key_match2?(key1, key2) do
    compiled =
      PatternCache.fetch(:key_match2, key2, fn ->
        match =
          key2
          |> String.replace("/*", "/.*")
          |> then(&Regex.replace(path_var_regex(), &1, "[^/]+"))

        case Regex.compile("^" <> match <> "$") do
          {:ok, r} -> {:ok, r}
          {:error, _} -> :error
        end
      end)

    case compiled do
      {:ok, r} -> Regex.match?(r, key1)
      :error -> false
    end
  end

  @doc """
  Returns the value matched by the path variable in `key2`.

  For example, `/resource1` matches `/:resource` and if `path_var` is `"resource"`,
  then `"resource1"` will be returned.

  ## Examples

      iex> Enforcer.key_get2("/resource1", "/:resource", "resource")
      "resource1"
      iex> Enforcer.key_get2("/myid/using/myresid", "/:id/using/:resId", "id")
      "myid"
      iex> Enforcer.key_get2("/myid/using/myresid", "/:id/using/:resId", "resId")
      "myresid"
  """
  @spec key_get2(String.t(), String.t(), String.t()) :: String.t()
  def key_get2(key1, key2, path_var) do
    compiled =
      PatternCache.fetch(:key_get2, key2, fn ->
        key2 = String.replace(key2, "/*", "/.*")
        keys = path_var_regex() |> Regex.scan(key2) |> Enum.map(fn [k] -> k end)
        replaced = Regex.replace(path_var_regex(), key2, "([^/]+)")

        case Regex.compile("^" <> replaced <> "$") do
          {:ok, r} -> {:ok, r, keys}
          {:error, _} -> :error
        end
      end)

    with {:ok, r2, keys} <- compiled,
         [_ | [_ | _] = values] <- Regex.run(r2, key1) do
      keys
      |> Enum.zip(values)
      |> Enum.find_value("", fn {k, v} ->
        if String.slice(k, 1..-1//1) == path_var, do: v
      end)
    else
      _ -> ""
    end
  end

  @doc """
  Returns `true` if `key1` matches the pattern of `key2`.

  Similar to `key_match2?/2` but uses `{resource}` syntax instead of `:resource`.

  ## Examples

      iex> Enforcer.key_match3?("/foo/bar", "/foo/*")
      true
      iex> Enforcer.key_match3?("/resource1", "/{resource}")
      true
      iex> Enforcer.key_match3?("/myid/using/myresid", "/{id}/using/{resId}")
      true
  """
  @spec key_match3?(String.t(), String.t()) :: boolean()
  def key_match3?(key1, key2) do
    compiled =
      PatternCache.fetch(:key_match3, key2, fn ->
        match =
          key2
          |> String.replace("/*", "/.*")
          |> then(&Regex.replace(brace_var_regex(), &1, "[^/]+"))

        case Regex.compile("^" <> match <> "$") do
          {:ok, r} -> {:ok, r}
          {:error, _} -> :error
        end
      end)

    case compiled do
      {:ok, r} -> Regex.match?(r, key1)
      :error -> false
    end
  end

  @doc """
  Returns `true` if `key1` matches the pattern of `key2`.

  Similar to `key_match3?/2` but enforces that repeated parameter names must have
  the same value. For example, `/parent/123/child/123` matches `/parent/{id}/child/{id}`
  but `/parent/123/child/456` does not.

  ## Examples

      iex> Enforcer.key_match4?("/parent/123/child/123", "/parent/{id}/child/{id}")
      true
      iex> Enforcer.key_match4?("/parent/123/child/456", "/parent/{id}/child/{id}")
      false
  """
  @spec key_match4?(String.t(), String.t()) :: boolean()
  def key_match4?(key1, key2) do
    compiled =
      PatternCache.fetch(:key_match4, key2, fn ->
        key2 = String.replace(key2, "/*", "/.*")

        tokens =
          brace_var_capture_regex()
          |> Regex.scan(key2)
          |> Enum.map(fn [_, token] -> token end)

        key2_pattern = Regex.replace(brace_var_capture_regex(), key2, "([^/]+)")

        case Regex.compile("^" <> key2_pattern <> "$") do
          {:ok, r} -> {:ok, r, tokens}
          {:error, _} -> :error
        end
      end)

    with {:ok, r2, tokens} <- compiled,
         [_ | values] <- Regex.run(r2, key1),
         true <- length(tokens) == length(values) do
      # Build a map of token -> value and check for conflicts
      tokens
      |> Enum.zip(values)
      |> Enum.reduce_while(%{}, fn {token, value}, acc ->
        case Map.get(acc, token) do
          nil -> {:cont, Map.put(acc, token, value)}
          ^value -> {:cont, acc}
          _ -> {:halt, :mismatch}
        end
      end)
      |> Kernel.!=(:mismatch)
    else
      _ -> false
    end
  end

  @doc """
  Returns `true` if IP address `ip1` matches the pattern of `ip2`.

  `ip2` can be an IP address or a CIDR pattern.

  ## Examples

      iex> Enforcer.ip_match?("192.168.2.123", "192.168.2.0/24")
      true
      iex> Enforcer.ip_match?("192.168.2.123", "192.168.2.123")
      true
      iex> Enforcer.ip_match?("192.168.2.123", "192.168.3.0/24")
      false
  """
  @spec ip_match?(String.t(), String.t()) :: boolean()
  def ip_match?(ip1, ip2) do
    case parse_ip(ip1) do
      {:ok, ip1_tuple} ->
        case parse_cidr(ip2) do
          {:ok, network, prefix_len} ->
            ip_in_cidr?(ip1_tuple, network, prefix_len)

          :error ->
            case parse_ip(ip2) do
              {:ok, ip2_tuple} -> ip1_tuple == ip2_tuple
              :error -> false
            end
        end

      :error ->
        false
    end
  end

  # Helper function to parse IP address
  defp parse_ip(ip_string) do
    case :inet.parse_address(String.to_charlist(ip_string)) do
      {:ok, ip_tuple} -> {:ok, ip_tuple}
      {:error, _} -> :error
    end
  end

  # Helper function to parse CIDR notation
  defp parse_cidr(cidr_string) do
    case String.split(cidr_string, "/") do
      [ip_str, prefix_str] ->
        with {:ok, ip_tuple} <- parse_ip(ip_str),
             {prefix_len, ""} <- Integer.parse(prefix_str) do
          {:ok, ip_tuple, prefix_len}
        else
          _ -> :error
        end

      _ ->
        :error
    end
  end

  # Check if an IP is within a CIDR range
  defp ip_in_cidr?(ip_tuple, network_tuple, prefix_len) do
    ip_bits = ip_to_bits(ip_tuple)
    network_bits = ip_to_bits(network_tuple)

    String.slice(ip_bits, 0, prefix_len) == String.slice(network_bits, 0, prefix_len)
  end

  # Convert IP tuple to binary string representation
  defp ip_to_bits({a, b, c, d}) do
    <<a, b, c, d>>
    |> :binary.bin_to_list()
    |> Enum.map(&Integer.to_string(&1, 2))
    |> Enum.map(&String.pad_leading(&1, 8, "0"))
    |> Enum.join()
  end

  defp ip_to_bits({a, b, c, d, e, f, g, h}) do
    # Convert each 16-bit segment to binary representation
    [a, b, c, d, e, f, g, h]
    |> Enum.map(&Integer.to_string(&1, 2))
    |> Enum.map(&String.pad_leading(&1, 16, "0"))
    |> Enum.join()
  end

  @doc """
  Returns `true` if `key1` matches the glob pattern `key2`.

  Uses standard glob pattern matching with `*` and `**` wildcards.
  - `*` matches any characters except `/`
  - `**` matches any characters including `/`

  ## Examples

      iex> Enforcer.glob_match?("/foo/bar", "/foo/*")
      true
      iex> Enforcer.glob_match?("/foo", "/foo")
      true
  """
  @spec glob_match?(String.t(), String.t()) :: boolean()
  def glob_match?(key1, key2) do
    compiled =
      PatternCache.fetch(:glob_match, key2, fn ->
        # Convert glob pattern to regex pattern
        # Process in order: escape dots, handle **, then handle *
        pattern =
          key2
          |> String.replace(".", "\\.")
          # Use null byte as temporary placeholder
          |> String.replace("**", "\x00")
          |> String.replace("*", "[^/]*")
          # Replace placeholder with .*
          |> String.replace("\x00", ".*")
          |> then(&("^" <> &1 <> "$"))

        case Regex.compile(pattern) do
          {:ok, regex} -> {:ok, regex}
          {:error, _} -> :error
        end
      end)

    case compiled do
      {:ok, regex} -> Regex.match?(regex, key1)
      :error -> false
    end
  end

  #
  # Helpers
  #

  # Constant helper regexes used to translate key patterns, compiled once
  # at module load instead of on every call.
  @path_var_regex ~r/:[^\/]+/
  @brace_var_regex ~r/\{[^\/]+\}/
  @brace_var_capture_regex ~r/\{([^\/]+)\}/

  defp path_var_regex, do: @path_var_regex
  defp brace_var_regex, do: @brace_var_regex
  defp brace_var_capture_regex, do: @brace_var_capture_regex

  defp init_env do
    %{
      regexMatch: &regex_match?/2,
      keyMatch: &key_match?/2,
      keyGet: &key_get/2,
      keyMatch2: &key_match2?/2,
      keyGet2: &key_get2/3,
      keyMatch3: &key_match3?/2,
      keyMatch4: &key_match4?/2,
      ipMatch: &ip_match?/2,
      globMatch: &glob_match?/2
    }
  end
end
