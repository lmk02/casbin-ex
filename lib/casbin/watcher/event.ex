defmodule Casbin.Watcher.Event do
  @moduledoc """
  A policy-change notification exchanged between enforcer instances
  through a `Casbin.Watcher` backend.

  Events are hints for cache invalidation, never the source of truth: the
  persist adapter's storage is authoritative, and receivers fall back to a
  full reload whenever an event cannot be applied incrementally (gaps in
  `revision`, unknown payloads, `:full_reload`).

  The wire format is JSON so a shared channel stays compatible with
  watchers of other Casbin implementations and never requires
  `:erlang.binary_to_term/1` on data from shared infrastructure.
  """

  @derive {Inspect, optional: [:field_index, :field_values, :ts]}
  defstruct v: 1,
            op: nil,
            ptype: nil,
            rules: [],
            field_index: nil,
            field_values: nil,
            instance_id: nil,
            revision: nil,
            enforcer: nil,
            ts: nil

  @type op ::
          :add_policy
          | :remove_policy
          | :remove_filtered_policy
          | :add_mapping_policy
          | :remove_mapping_policy
          | :full_reload

  @type t :: %__MODULE__{
          v: pos_integer(),
          op: op(),
          ptype: atom() | nil,
          rules: [[String.t()]],
          field_index: non_neg_integer() | nil,
          field_values: [String.t()] | nil,
          instance_id: String.t() | nil,
          revision: non_neg_integer() | nil,
          enforcer: String.t() | nil,
          ts: non_neg_integer() | nil
        }

  @ops ~w(add_policy remove_policy remove_filtered_policy add_mapping_policy remove_mapping_policy full_reload)a
  @op_strings Map.new(@ops, fn op -> {Atom.to_string(op), op} end)

  @doc """
  Encodes the event as a JSON binary.
  """
  @spec encode!(t()) :: binary()
  def encode!(%__MODULE__{} = event) do
    %{
      "v" => event.v,
      "op" => Atom.to_string(event.op),
      "ptype" => event.ptype && Atom.to_string(event.ptype),
      "rules" => event.rules,
      "field_index" => event.field_index,
      "field_values" => event.field_values,
      "instance_id" => event.instance_id,
      "revision" => event.revision,
      "enforcer" => event.enforcer,
      "ts" => event.ts
    }
    |> json_encode!()
  end

  @doc """
  Decodes a JSON binary into an event.

  Returns `{:error, reason}` for malformed JSON, unknown operations or
  unknown policy types; callers should log and drop such payloads.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, term()}
  def decode(payload) when is_binary(payload) do
    with {:ok, map} when is_map(map) <- json_decode(payload),
         {:ok, op} <- decode_op(map["op"]),
         {:ok, ptype} <- decode_ptype(map["ptype"]) do
      {:ok,
       %__MODULE__{
         v: map["v"] || 1,
         op: op,
         ptype: ptype,
         rules: map["rules"] || [],
         field_index: map["field_index"],
         field_values: map["field_values"],
         instance_id: map["instance_id"],
         revision: map["revision"],
         enforcer: map["enforcer"],
         ts: map["ts"]
       }}
    else
      {:ok, other} -> {:error, {:unexpected_payload, other}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_op(op) when is_map_key(@op_strings, op), do: {:ok, @op_strings[op]}
  defp decode_op(op), do: {:error, {:unknown_op, op}}

  defp decode_ptype(nil), do: {:ok, nil}

  defp decode_ptype(ptype) when is_binary(ptype) do
    # Policy-type atoms (:p, :g, ...) already exist from the loaded model;
    # anything else is an unknown ptype, not a reason to create atoms from
    # wire data.
    {:ok, String.to_existing_atom(ptype)}
  rescue
    ArgumentError -> {:error, {:unknown_ptype, ptype}}
  end

  defp decode_ptype(other), do: {:error, {:unknown_ptype, other}}

  # JSON codec: use Jason when available (optional dependency), otherwise
  # the JSON module built into Elixir >= 1.18.
  cond do
    Code.ensure_loaded?(Jason) ->
      defp json_encode!(map), do: Jason.encode!(map)

      defp json_decode(payload) do
        case Jason.decode(payload) do
          {:ok, decoded} -> {:ok, decoded}
          {:error, reason} -> {:error, {:invalid_json, reason}}
        end
      end

    Code.ensure_loaded?(JSON) ->
      defp json_encode!(map), do: JSON.encode!(map)

      defp json_decode(payload) do
        {:ok, JSON.decode!(payload)}
      rescue
        error -> {:error, {:invalid_json, error}}
      end

    true ->
      defp json_encode!(_map) do
        raise "Casbin.Watcher.Event requires a JSON codec: add {:jason, \"~> 1.4\"} " <>
                "to your dependencies or use Elixir >= 1.18"
      end

      defp json_decode(_payload) do
        raise "Casbin.Watcher.Event requires a JSON codec: add {:jason, \"~> 1.4\"} " <>
                "to your dependencies or use Elixir >= 1.18"
      end
  end
end
