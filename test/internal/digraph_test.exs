defmodule Casbin.Internal.DigraphTest do
  use ExUnit.Case, async: true
  alias Casbin.Internal.Digraph
  doctest Casbin.Internal.Digraph

  describe "has_path?/3 on graphs with revisited vertices" do
    # Regression: the DFS accumulator used to be replaced by `false` when a
    # neighbor had already been visited, crashing or misreporting on any
    # graph where two paths reach the same vertex.
    test "triangle graph a->b, b->c, a->c" do
      g =
        Digraph.new()
        |> Digraph.add_edge({:a, :b})
        |> Digraph.add_edge({:b, :c})
        |> Digraph.add_edge({:a, :c})

      assert Digraph.has_path?(g, :a, :b)
      assert Digraph.has_path?(g, :a, :c)
      assert Digraph.has_path?(g, :b, :c)
      refute Digraph.has_path?(g, :c, :a)
      refute Digraph.has_path?(g, :b, :a)
    end

    test "diamond graph a->b, a->c, b->d, c->d" do
      g =
        Digraph.new()
        |> Digraph.add_edge({:a, :b})
        |> Digraph.add_edge({:a, :c})
        |> Digraph.add_edge({:b, :d})
        |> Digraph.add_edge({:c, :d})

      assert Digraph.has_path?(g, :a, :d)
      assert Digraph.has_path?(g, :b, :d)
      refute Digraph.has_path?(g, :d, :a)
      refute Digraph.has_path?(g, :b, :c)
    end

    test "cyclic graph terminates" do
      g =
        Digraph.new()
        |> Digraph.add_edge({:a, :b})
        |> Digraph.add_edge({:b, :c})
        |> Digraph.add_edge({:c, :a})

      assert Digraph.has_path?(g, :a, :c)
      assert Digraph.has_path?(g, :c, :b)
    end

    test "matches :digraph reference on a random DAG" do
      edges =
        for v <- 1..40, w <- (v + 1)..41, :erlang.phash2({v, w}, 7) == 0 do
          {v, w}
        end

      g = Enum.reduce(edges, Digraph.new(), &Digraph.add_edge(&2, &1))

      ref = :digraph.new()
      for v <- 1..41, do: :digraph.add_vertex(ref, v)
      for {v, w} <- edges, do: :digraph.add_edge(ref, v, w)

      for v <- 1..41, w <- 1..41, v != w do
        expected = :digraph.get_path(ref, v, w) != false
        assert Digraph.has_path?(g, v, w) == expected, "mismatch for #{v} -> #{w}"
      end

      :digraph.delete(ref)
    end
  end
end
