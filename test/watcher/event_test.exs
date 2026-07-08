defmodule Casbin.Watcher.EventTest do
  use ExUnit.Case, async: true

  alias Casbin.Watcher.Event

  test "round-trips a policy event" do
    event = %Event{
      op: :add_policy,
      ptype: :p,
      rules: [["alice", "data1", "read"]],
      instance_id: "abc",
      revision: 42,
      enforcer: "acl",
      ts: 1_700_000_000_000
    }

    assert {:ok, decoded} = event |> Event.encode!() |> Event.decode()
    assert decoded == event
  end

  test "round-trips a filtered-remove event" do
    event = %Event{
      op: :remove_filtered_policy,
      ptype: :p,
      field_index: 0,
      field_values: ["alice"],
      instance_id: "abc",
      revision: 7
    }

    assert {:ok, decoded} = event |> Event.encode!() |> Event.decode()
    assert decoded == event
  end

  test "round-trips a full_reload event without ptype" do
    event = %Event{op: :full_reload, instance_id: "abc", revision: 9}
    assert {:ok, decoded} = event |> Event.encode!() |> Event.decode()
    assert decoded == event
  end

  test "rejects malformed JSON" do
    assert {:error, {:invalid_json, _}} = Event.decode("{nope")
  end

  test "rejects unknown ops" do
    assert {:error, {:unknown_op, "drop_table"}} = Event.decode(~s({"op":"drop_table"}))
  end

  test "rejects unknown ptypes instead of creating atoms" do
    payload = ~s({"op":"add_policy","ptype":"definitely_not_an_existing_atom_xyz"})
    assert {:error, {:unknown_ptype, _}} = Event.decode(payload)
  end

  test "rejects non-object payloads" do
    assert {:error, {:unexpected_payload, _}} = Event.decode("[1,2,3]")
  end
end
