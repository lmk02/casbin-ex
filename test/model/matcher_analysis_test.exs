defmodule Casbin.Model.MatcherAnalysisTest do
  use ExUnit.Case, async: true

  alias Casbin.Model.Matcher
  alias Casbin.Model.MatcherAnalysis
  alias Casbin.Model.MatcherAnalysis.Plan
  alias Casbin.Model.Policy

  defp plan(matcher_string, role_mappings \\ []) do
    %Matcher{ast: ast} = Matcher.new(matcher_string)
    MatcherAnalysis.analyze(ast, role_mappings)
  end

  test "plain ACL matcher indexes all three attributes" do
    assert %Plan{ptype: :p, attrs: [:sub, :obj, :act], sources: [eq: :sub, eq: :obj, eq: :act]} =
             plan("r.sub == p.sub && r.obj == p.obj && r.act == p.act")
  end

  test "reversed equality operands are recognized" do
    assert %Plan{attrs: [:sub], sources: [eq: :sub]} = plan("p.sub == r.sub")
  end

  test "RBAC matcher indexes the role position through g" do
    assert %Plan{attrs: [:obj, :act, :sub], sources: [{:eq, :obj}, {:eq, :act}, {:g, :g, :sub}]} =
             plan("g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act", [:g])
  end

  test "g calls are only indexed for known role mappings" do
    assert plan("g(r.sub, p.sub)", []) == nil
    assert %Plan{sources: [{:g, :g, :sub}]} = plan("g(r.sub, p.sub)", [:g])
  end

  test "pattern functions are not indexed but eq conjuncts still are" do
    assert %Plan{attrs: [:sub], sources: [eq: :sub]} =
             plan("r.sub == p.sub && keyMatch2(r.obj, p.obj)")
  end

  test "top-level disjunctions yield no plan" do
    assert plan("r.sub == p.sub || r.sub == \"root\"") == nil
  end

  test "index_key extracts the plan attributes from a policy" do
    plan = plan("r.sub == p.sub && r.act == p.act")
    policy = %Policy{key: :p, attrs: [sub: "alice", obj: "data1", act: "read", eft: "allow"]}

    assert MatcherAnalysis.index_key(plan, policy) == {"alice", "read"}
    assert MatcherAnalysis.index_key(nil, policy) == :full
    assert MatcherAnalysis.index_key(plan, %Policy{key: :p2, attrs: []}) == :full
  end
end
