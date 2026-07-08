defmodule Casbin.Internal.RoleGroup do
  @moduledoc """
  This module defines a structure to manage the roles and their inheritances
  in the (H)RBAC model.

  The `RoleGroup` struct is structured like so:
  - An atom to represent the name of the group (`name`).
  - A directed graph to manage the roles and their inheritances (`role_graph`)
  """

  defstruct name: nil, role_graph: nil

  alias Casbin.Internal.Digraph
  alias Casbin.Internal.PatternCache
  alias Casbin.Store

  @type role_type() :: term()

  @type t() :: %__MODULE__{
          name: atom(),
          role_graph: Digraph.t()
        }

  @doc """
  Creates a new role group
  """
  @spec new(atom()) :: t()
  def new(a), do: %__MODULE__{name: a, role_graph: Digraph.new()}

  @doc """
  Returns the list of all roles in the given role group.

  ## Examples

      iex> g = RoleGroup.new(:g) |> RoleGroup.add_roles(["admin", "member"])
      ...> RoleGroup.list_roles(g) -- ["admin", "member"]
      []
  """
  @spec list_roles(t()) :: [role_type()]
  def list_roles(%__MODULE__{role_graph: g}) do
    g |> Digraph.list_vertices()
  end

  @doc """
  Adds a new role to the group. If the given role is already present, this
  is a no-op.

  ## Examples

      iex> g = RoleGroup.new(:g) |> RoleGroup.add_role("admin")
      ...> g = g |> RoleGroup.add_role("admin")
      ...> g |> RoleGroup.list_roles()
      ["admin"]
  """
  @spec add_role(t(), role_type()) :: t()
  def add_role(%__MODULE__{role_graph: g} = group, new_role) do
    %{group | role_graph: g |> Digraph.add_vertex(new_role)}
  end

  @doc """
  Like `add_role/1`, but takes a list of roles.

  ## Examples

      iex> g = RoleGroup.new(:g) |> RoleGroup.add_roles(["admin", "member"])
      ...> RoleGroup.list_roles(g) -- ["admin", "member"]
      []
  """
  @spec add_roles(t(), [role_type()]) :: t()
  def add_roles(%__MODULE__{role_graph: g} = group, roles)
      when is_list(roles) do
    %{group | role_graph: g |> Digraph.add_vertices(roles)}
  end

  @doc """
  Makes role `r1` inherits from role `r2`. If any of the two roles `r1`,
  `r2` is not present in the group, it'll be created and new inheritance
  will be added.

  If role `r1` already inherits from role `r2`, this is a no-op.

  ## Examples

      iex> pair = {"admin", "member"}
      ...> g = RoleGroup.new(:g) |> RoleGroup.add_inheritance(pair)
      ...> true = g |> RoleGroup.inherit_from?("admin", "member")
      ...> g |> RoleGroup.inherit_from?("member", "admin")
      false
  """
  @spec add_inheritance(t(), {role_type(), role_type()}) :: t()
  def add_inheritance(%__MODULE__{role_graph: g} = group, {r1, r2}) do
    purge_reachability(g)
    %{group | role_graph: g |> Digraph.add_edge({r1, r2})}
  end

  @doc """
  Removes the inheritance connection between roles

  ## Examples

      iex> pair = {"admin", "member"}
      ...> g = RoleGroup.new(:g) |> RoleGroup.add_inheritance(pair)
      ...> true = g |> RoleGroup.inherit_from?("admin", "member")
      ...> false = g |> RoleGroup.inherit_from?("member", "admin")
      ...> g = g |> RoleGroup.remove_inheritance(pair)
      ...> false = g |> RoleGroup.inherit_from?("admin", "member")
  """
  @spec remove_inheritance(t(), {role_type(), role_type()}) :: t()
  def remove_inheritance(%__MODULE__{role_graph: g} = group, {r1, r2}) do
    purge_reachability(g)
    %{group | role_graph: g |> Digraph.remove_edge({r1, r2})}
  end

  # Evicts memoized reachability results for the graph version being
  # superseded (see PatternCache): pair membership and candidate names.
  defp purge_reachability(%Digraph{version: version}) do
    PatternCache.purge(:role_reach, version)
    PatternCache.purge(:role_names, version)
  end

  @doc """
  Returns `true` if role `r1` inherits from role `r2`.
  Returns `false`, otherwise.

  NOTE: role inheritance is transitive, meaning if `A` inherits from `B`,
  `B` inherits from `C`, then `A` inherits from `C`.

  ## Examples

      iex> g = RoleGroup.new(:g)
      ...> g = g |> RoleGroup.add_inheritance({"author", "reader"})
      ...> g = g |> RoleGroup.add_inheritance({"admin", "author"})
      ...> true = g |> RoleGroup.inherit_from?("author","author")
      ...> true = g |> RoleGroup.inherit_from?("author", "reader")
      ...> false = g |> RoleGroup.inherit_from?("reader", "author")
      ...> true = g |> RoleGroup.inherit_from?("admin", "author")
      ...> false = g |> RoleGroup.inherit_from?("author", "admin")
      ...> false = g |> RoleGroup.inherit_from?("reader", "admin")
      ...> g |> RoleGroup.inherit_from?("admin", "reader")
      true
  """
  @spec inherit_from?(t(), role_type(), role_type()) :: boolean()
  def inherit_from?(%__MODULE__{role_graph: g}, r1, r2) do
    r1 === r2 || g |> Digraph.has_path?(r1, r2)
  end

  # inherit_from? backed by a memoized reachable set: the full DFS from
  # `r1` runs once per (graph version, r1) instead of once per matcher
  # evaluation — i.e. once instead of policies × requests times. Keyed by
  # the graph's version reference, which changes on every edge mutation.
  defp cached_inherit_from?(%Digraph{} = g, r1, r2) do
    r1 === r2 ||
      :role_reach
      |> PatternCache.fetch({g.version, r1}, fn -> Digraph.reachable(g, r1) end)
      |> Digraph.reachable_id?(r2)
  end

  @doc """
  Returns a function used when evaluating a matcher program.

  ## Examples

      iex> g = RoleGroup.new(:g)
      ...> g = g |> RoleGroup.add_inheritance({"admin", "member"})
      ...> f = g |> RoleGroup.stub_2
      ...> false = f.("member", "admin")
      ...> false = f.(1, 2)
      ...> f.("admin", "member")
      true
      ...> g = g |> RoleGroup.add_inheritance({{"admin", "domain"}, {"member", "domain"}})
      ...> f = g |> RoleGroup.stub_3
      ...> false = f.("member", "admin", "domain")
      ...> f.("admin", "member", "domain")
      true
  """
  def stub_2(%__MODULE__{role_graph: g}) do
    fn
      arg1, arg2 ->
        cached_inherit_from?(g, arg1, arg2)
    end
  end

  def stub_3(%__MODULE__{role_graph: g}) do
    fn
      arg1, arg2, arg3 ->
        cached_inherit_from?(g, {arg1, arg3}, {arg2, arg3})
    end
  end

  @doc """
  Like `stub_2/1`, but resolves the role graph through `Casbin.Store`
  instead of capturing it in the closure. Used for the env projected into
  the shared core row, which must stay small: the graph is only loaded
  from ETS on a reachability-cache miss, never per call.
  """
  def ets_stub_2(ename, gname, version) do
    fn
      arg1, arg2 ->
        ets_cached_inherit_from?(ename, gname, version, arg1, arg2)
    end
  end

  @doc """
  Domain variant of `ets_stub_2/3`.
  """
  def ets_stub_3(ename, gname, version) do
    fn
      arg1, arg2, arg3 ->
        ets_cached_inherit_from?(ename, gname, version, {arg1, arg3}, {arg2, arg3})
    end
  end

  defp ets_cached_inherit_from?(ename, gname, version, r1, r2) do
    r1 === r2 ||
      :role_reach
      |> PatternCache.fetch({version, r1}, fn ->
        case Store.fetch_role_graph(ename, gname) do
          %Digraph{version: ^version} = graph ->
            Digraph.reachable(graph, r1)

          %Digraph{} = graph ->
            # The projected graph is from a different (usually newer)
            # generation than this stub: answer from it, but do not poison
            # the cache entry for `version`.
            {:nocache, Digraph.reachable(graph, r1)}

          nil ->
            {:nocache, MapSet.new()}
        end
      end)
      |> Digraph.reachable_id?(r2)
  end
end
