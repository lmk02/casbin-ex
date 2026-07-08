defmodule Casbin.Persist.Revision do
  @moduledoc """
  A monotonic revision counter per enforcer scope, stored next to the
  policies in the `casbin_revision` table.

  The counter serves two purposes in multi-instance deployments:

    * every published `Casbin.Watcher.Event` carries the revision produced
      by `bump/2`, giving receivers a total order to detect duplicate,
      stale or missed events;
    * `current/2` is a cheap single-row read that reconciliation timers
      poll to detect drift without reloading the full policy set.

  Requires a migration such as:

      create table(:casbin_revision, primary_key: false) do
        add(:scope, :text, primary_key: true)
        add(:revision, :bigint, null: false, default: 0)
        add(:updated_at, :utc_datetime_usec, null: false)
      end
  """

  use Ecto.Schema

  @primary_key {:scope, :string, autogenerate: false}
  schema "casbin_revision" do
    field(:revision, :integer, default: 0)
    field(:updated_at, :utc_datetime_usec)
  end

  @doc """
  Atomically increments and returns the revision for `scope`, creating
  the row on first use.
  """
  @spec bump(module(), String.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def bump(repo, scope) when is_atom(repo) and is_binary(scope) do
    now = DateTime.utc_now()

    %__MODULE__{scope: scope, revision: 1, updated_at: now}
    |> repo.insert(
      on_conflict: [inc: [revision: 1], set: [updated_at: now]],
      conflict_target: :scope,
      returning: [:revision]
    )
    |> case do
      {:ok, %__MODULE__{revision: revision}} -> {:ok, revision}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Returns the current revision for `scope` (0 if never bumped).
  """
  @spec current(module(), String.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def current(repo, scope) when is_atom(repo) and is_binary(scope) do
    case repo.get(__MODULE__, scope) do
      nil -> {:ok, 0}
      %__MODULE__{revision: revision} -> {:ok, revision}
    end
  rescue
    error -> {:error, error}
  end
end
