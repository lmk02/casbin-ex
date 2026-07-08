defmodule Casbin.Enforcer.EffectSemanticsTest do
  # Pins down the decision semantics of both policy effects so the
  # short-circuiting `Enforcer.allow?/2` stays equivalent to matching the
  # full policy list and folding the effect afterwards.
  use ExUnit.Case, async: true

  alias Casbin.Enforcer

  @allow_conf "../data/acl.conf" |> Path.expand(__DIR__)
  @deny_conf "../data/deny_override.conf" |> Path.expand(__DIR__)

  describe "some(where (p.eft == allow))" do
    test "no matched policy denies" do
      {:ok, e} = Enforcer.init(@allow_conf)
      refute Enforcer.allow?(e, ["alice", "blog_post", "read"])
    end

    test "a matched allow policy allows even when a matched deny policy exists" do
      {:ok, e} = Enforcer.init(@allow_conf)

      e =
        e
        |> Enforcer.add_policy!({:p, ["alice", "blog_post", "read", "deny"]})
        |> Enforcer.add_policy!({:p, ["alice", "blog_post", "read"]})

      assert Enforcer.allow?(e, ["alice", "blog_post", "read"])
      refute Enforcer.allow?(e, ["alice", "blog_post", "write"])
    end

    test "only matched deny policies deny" do
      {:ok, e} = Enforcer.init(@allow_conf)
      e = Enforcer.add_policy!(e, {:p, ["alice", "blog_post", "read", "deny"]})
      refute Enforcer.allow?(e, ["alice", "blog_post", "read"])
    end
  end

  describe "!some(where (p.eft == deny))" do
    test "no matched policy allows" do
      {:ok, e} = Enforcer.init(@deny_conf)
      assert Enforcer.allow?(e, ["alice", "blog_post", "read"])
    end

    test "a matched allow policy allows" do
      {:ok, e} = Enforcer.init(@deny_conf)
      e = Enforcer.add_policy!(e, {:p, ["alice", "blog_post", "read"]})
      assert Enforcer.allow?(e, ["alice", "blog_post", "read"])
    end

    test "a matched deny policy denies even when a matched allow policy exists" do
      {:ok, e} = Enforcer.init(@deny_conf)

      e =
        e
        |> Enforcer.add_policy!({:p, ["alice", "blog_post", "read"]})
        |> Enforcer.add_policy!({:p, ["alice", "blog_post", "read", "deny"]})

      refute Enforcer.allow?(e, ["alice", "blog_post", "read"])
    end
  end

  describe "policy set bookkeeping" do
    test "re-adding after remove_policy works" do
      {:ok, e} = Enforcer.init(@allow_conf)
      rule = {:p, ["alice", "blog_post", "read"]}

      e = Enforcer.add_policy!(e, rule)
      assert {:error, :already_existed} = Enforcer.add_policy(e, rule)

      e = Enforcer.remove_policy!(e, rule)
      assert {:error, :nonexistent} = Enforcer.remove_policy(e, rule)

      e = Enforcer.add_policy!(e, rule)
      assert Enforcer.allow?(e, ["alice", "blog_post", "read"])
    end

    test "re-adding after remove_filtered_policy works" do
      {:ok, e} = Enforcer.init(@allow_conf)

      e =
        e
        |> Enforcer.add_policy!({:p, ["alice", "blog_post", "read"]})
        |> Enforcer.add_policy!({:p, ["alice", "comment", "read"]})
        |> Enforcer.remove_filtered_policy!(:p, 0, ["alice"])

      assert Enforcer.list_policies(e) == []

      e = Enforcer.add_policy!(e, {:p, ["alice", "blog_post", "read"]})
      assert Enforcer.allow?(e, ["alice", "blog_post", "read"])
    end
  end
end
