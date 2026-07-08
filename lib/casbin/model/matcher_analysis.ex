defmodule Casbin.Model.MatcherAnalysis do
  @moduledoc """
  Static analysis of a matcher expression to derive a policy index plan.

  The plan identifies policy attributes whose value any matching policy
  must satisfy exactly, given a request:

    * `r.X == p.Y` conjuncts — the matching policy's `Y` must equal the
      request's `X`
    * `g(r.X, p.Y)` conjuncts — the matching policy's `Y` must be `r.X`
      itself or a role reachable from it in the `g` role graph

  `Casbin.Store` keys policy rows by the tuple of these attribute values,
  and `Casbin.Runtime` probes only the buckets a request can possibly
  match instead of scanning every policy. The index only prunes: the full
  matcher still evaluates over every candidate, so an imprecise plan can
  never change a decision, and matchers that don't decompose into a
  top-level conjunction simply yield no plan (full scan, as before).
  """

  defmodule Plan do
    @moduledoc """
    A policy index plan. `attrs` are the indexed policy attributes;
    `sources` (aligned with `attrs`) say how request-side candidate
    values are derived per position.
    """
    defstruct ptype: nil, attrs: [], sources: []

    @type source :: {:eq, atom()} | {:g, atom(), atom()}
    @type t :: %__MODULE__{ptype: atom(), attrs: [atom()], sources: [source()]}
  end

  @doc """
  Derives a `Plan` from the matcher AST, or `nil` when nothing indexable
  is found. `role_mappings` is the list of role-mapping names (`[:g]`),
  used to recognize role-function calls.
  """
  @spec analyze(term(), [atom()]) :: Plan.t() | nil
  def analyze(ast, role_mappings) when is_list(role_mappings) do
    entries =
      ast
      |> conjuncts()
      |> Enum.flat_map(&indexable_entry(&1, role_mappings))

    case entries do
      [] -> nil
      entries -> build_plan(entries)
    end
  end

  def analyze(_ast, _role_mappings), do: nil

  defp build_plan(entries) do
    entries = dedup_attrs(entries)
    {eq, g} = Enum.split_with(entries, fn {_pt, _pa, source} -> match?({:eq, _}, source) end)

    # A single role expansion keeps the candidate product small; extra
    # g-conjuncts still filter through the matcher itself.
    entries = eq ++ Enum.take(g, 1)

    case entries |> Enum.map(fn {pt, _, _} -> pt end) |> Enum.uniq() do
      [ptype] ->
        %Plan{
          ptype: ptype,
          attrs: Enum.map(entries, fn {_, pa, _} -> pa end),
          sources: Enum.map(entries, fn {_, _, source} -> source end)
        }

      _mixed_or_empty ->
        nil
    end
  end

  @doc """
  Computes the index key of `policy` under `plan`: the tuple of its
  values at the plan's attributes, or `:full` when the policy cannot be
  indexed (different policy type or missing attribute) and must live in
  the always-scanned bucket.
  """
  @spec index_key(Plan.t() | nil, Casbin.Model.Policy.t()) :: tuple() | :full
  def index_key(nil, _policy), do: :full

  def index_key(%Plan{ptype: ptype, attrs: attrs}, %{key: ptype} = policy) do
    values = Enum.map(attrs, fn attr -> policy.attrs[attr] end)

    if Enum.any?(values, &is_nil/1) do
      :full
    else
      List.to_tuple(values)
    end
  end

  def index_key(%Plan{}, _policy), do: :full

  # A top-level && chain decomposes into conjuncts; anything else is a
  # single conjunct (an :or / :not root then simply yields no entries).
  defp conjuncts({:and, lhs, rhs}), do: conjuncts(lhs) ++ conjuncts(rhs)
  defp conjuncts(expr), do: [expr]

  defp indexable_entry({:eq, {:dot, :r, r_attr}, {:dot, p, p_attr}}, _mappings) when p != :r,
    do: [{p, p_attr, {:eq, r_attr}}]

  defp indexable_entry({:eq, {:dot, p, p_attr}, {:dot, :r, r_attr}}, _mappings) when p != :r,
    do: [{p, p_attr, {:eq, r_attr}}]

  defp indexable_entry({:call, name, [{:dot, :r, r_attr}, {:dot, p, p_attr}]}, mappings)
       when p != :r do
    if name in mappings, do: [{p, p_attr, {:g, name, r_attr}}], else: []
  end

  defp indexable_entry(_expr, _mappings), do: []

  # The same policy attribute constrained twice keeps only the first
  # entry — one exact position per attribute suffices for pruning.
  defp dedup_attrs(entries) do
    Enum.uniq_by(entries, fn {pt, pa, _} -> {pt, pa} end)
  end
end
