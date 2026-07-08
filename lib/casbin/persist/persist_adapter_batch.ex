defprotocol Casbin.Persist.PersistAdapterBatch do
  @moduledoc """
  Optional batch extension of `Casbin.Persist.PersistAdapter`.

  A companion protocol (instead of new functions on `PersistAdapter`) so
  existing third-party adapters keep working unchanged: the `Any`
  fallback degrades batches to per-rule calls, while adapters that
  implement this protocol (like the Ecto adapter) persist a batch in a
  handful of round trips.
  """

  @fallback_to_any true

  @doc "Persists all `rules` (list of `{key, attrs}`)."
  def add_policies(adapter, rules)

  @doc "Removes all `rules` (list of `{key, attrs}`) from storage."
  def remove_policies(adapter, rules)
end

defimpl Casbin.Persist.PersistAdapterBatch, for: Casbin.Persist.EctoAdapter do
  import Ecto.Query, only: [dynamic: 1, dynamic: 2, from: 2]

  alias Casbin.Persist.EctoAdapter
  alias Casbin.Persist.EctoAdapter.CasbinRule

  # 8 columns x 2000 rows stays well below parameter limits
  @insert_chunk 2_000
  # OR-of-conjunctions per delete query
  @remove_chunk 200

  def add_policies(%EctoAdapter{repo: nil, get_dynamic_repo: nil}, _rules),
    do: {:error, "repo is not set"}

  def add_policies(adapter, rules) do
    repo = EctoAdapter.get_repo(adapter)

    rules
    |> Enum.map(&CasbinRule.policy_to_map/1)
    |> Enum.chunk_every(@insert_chunk)
    |> Enum.each(fn chunk ->
      repo.insert_all(CasbinRule, chunk, on_conflict: :nothing)
    end)

    {:ok, adapter}
  end

  def remove_policies(%EctoAdapter{repo: nil, get_dynamic_repo: nil}, _rules),
    do: {:error, "repo is not set"}

  def remove_policies(adapter, rules) do
    repo = EctoAdapter.get_repo(adapter)

    rules
    |> Enum.chunk_every(@remove_chunk)
    |> Enum.each(fn chunk ->
      conditions =
        Enum.reduce(chunk, dynamic(false), fn rule, disjunction ->
          conjunction =
            rule
            |> CasbinRule.policy_to_map()
            |> Enum.reduce(dynamic(true), fn {column, value}, acc ->
              dynamic([r], field(r, ^column) == ^value and ^acc)
            end)

          dynamic([r], ^conjunction or ^disjunction)
        end)

      repo.delete_all(from(r in CasbinRule, where: ^conditions))
    end)

    {:ok, adapter}
  end
end

defimpl Casbin.Persist.PersistAdapterBatch, for: Any do
  alias Casbin.Persist.PersistAdapter

  def add_policies(adapter, rules), do: each_rule(adapter, rules, &PersistAdapter.add_policy/2)

  def remove_policies(adapter, rules),
    do: each_rule(adapter, rules, &PersistAdapter.remove_policy/2)

  defp each_rule(adapter, rules, fun) do
    Enum.reduce_while(rules, {:ok, adapter}, fn rule, {:ok, adapter} ->
      case fun.(adapter, rule) do
        {:ok, adapter} -> {:cont, {:ok, adapter}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end
end
