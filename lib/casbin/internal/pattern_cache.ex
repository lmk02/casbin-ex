defmodule Casbin.Internal.PatternCache do
  @moduledoc """
  Process-shared memoization of compiled matcher patterns.

  The built-in matching functions (`regexMatch`, `keyMatch2/3/4`,
  `keyGet2`, `globMatch`) receive their pattern from a policy rule, so
  the set of distinct patterns is bounded by the policy set and constant
  across requests — while the functions themselves run once per
  (request × policy) pair. Caching the fully transformed, compiled
  pattern turns the dominant per-call regex compilation into a single ETS
  read.

  Entries are only ever added (policies rarely change patterns), and the
  table is capped: beyond `max_entries` new patterns are compiled without
  being cached, which protects against unbounded growth if patterns are
  derived from request data.
  """

  @table :casbin_patterns
  @max_entries 100_000

  @doc """
  Creates the cache table; called once from the application supervisor.
  """
  def ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [
        :set,
        :public,
        :named_table,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    :ok
  end

  @doc """
  Returns the cached value for `{tag, key}`, invoking `builder` (and
  caching its result — including error results) on a miss.
  """
  @spec fetch(atom(), term(), (-> term())) :: term()
  def fetch(tag, pattern, builder) when is_atom(tag) and is_function(builder, 0) do
    key = {tag, pattern}

    case :ets.lookup(@table, key) do
      [{^key, value}] ->
        value

      [] ->
        case builder.() do
          # builder opted out of caching (e.g. it produced a result from
          # data it could not verify as current)
          {:nocache, value} ->
            value

          value ->
            if :ets.info(@table, :size) < @max_entries do
              :ets.insert_new(@table, {key, value})
            end

            value
        end
    end
  rescue
    # Table not available (enforcer used without the :casbin application
    # running): fall back to uncached compilation.
    ArgumentError -> builder.()
  end

  @doc """
  Deletes all entries whose key is `{tag, {prefix, _}}`. Used to evict
  memoized results tied to a superseded version (e.g. role-graph
  reachability after an inheritance change) so they don't count against
  the size cap.
  """
  @spec purge(atom(), term()) :: :ok
  def purge(tag, prefix) when is_atom(tag) do
    :ets.match_delete(@table, {{tag, {prefix, :_}}, :_})
    :ok
  rescue
    ArgumentError -> :ok
  end
end
