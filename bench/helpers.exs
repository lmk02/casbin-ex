defmodule Casbin.Bench.Helpers do
  @moduledoc """
  Shared fixture builders for the benchmark scripts.

  Policies are generated in memory and loaded through the public API with
  the default read-only adapter, so no external storage is required.
  """

  alias Casbin.Enforcer

  @data_dir Path.expand("../test/data", __DIR__)

  def conf(name), do: Path.join(@data_dir, name)

  @doc """
  ACL enforcer with `n` distinct `p, sub_i, obj_i, read` rules.

  Policies are prepended on add, so `sub0` ends up at the tail of the
  policy list (worst case for a scan) and `sub{n-1}` at the head.
  """
  def acl(n) do
    {:ok, e} = Enforcer.init(conf("acl.conf"))

    Enum.reduce(0..(n - 1), e, fn i, e ->
      Enforcer.add_policy!(e, {:p, ["sub#{i}", "obj#{i}", "read"]})
    end)
  end

  @doc """
  keyMatch2 enforcer with `n` pattern rules `p, sub{i}, /res{i}/:id, GET`.
  """
  def keymatch2(n) do
    {:ok, e} = Enforcer.init(conf("keymatch2.conf"))

    Enum.reduce(0..(n - 1), e, fn i, e ->
      Enforcer.add_policy!(e, {:p, ["sub#{i}", "/res#{i}/:id", "GET"]})
    end)
  end

  @doc """
  RBAC enforcer with `n` permission rules spread over `roles` roles, one
  user per role, and a role chain `role_0 -> role_1 -> ... -> role_{roles-1}`
  so low-numbered users resolve deep inheritance paths.
  """
  def rbac(n, roles \\ 100) do
    {:ok, e} = Enforcer.init(conf("rbac.conf"))

    e =
      Enum.reduce(0..(n - 1), e, fn i, e ->
        Enforcer.add_policy!(e, {:p, ["role#{rem(i, roles)}", "obj#{i}", "read"]})
      end)

    e =
      Enum.reduce(0..(roles - 1), e, fn j, e ->
        Enforcer.add_mapping_policy!(e, {:g, "user#{j}", "role#{j}"})
      end)

    Enum.reduce(0..(roles - 2), e, fn j, e ->
      Enforcer.add_mapping_policy!(e, {:g, "role#{j}", "role#{j + 1}"})
    end)
  end

  @doc "Requests hitting the head/tail of the policy list, plus a miss."
  def acl_requests(n) do
    %{
      hit_head: ["sub#{n - 1}", "obj#{n - 1}", "read"],
      hit_tail: ["sub0", "obj0", "read"],
      miss: ["nobody", "nothing", "read"]
    }
  end
end
