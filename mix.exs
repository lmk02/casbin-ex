defmodule Casbin.MixProject do
  use Mix.Project

  def project do
    [
      app: :casbin,
      version: "1.7.0",
      elixir: "~> 1.13",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: "https://github.com/casbin/casbin-ex",
      homepage_url: "https://casbin.org"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {Casbin, []}
    ]
  end

  # specifies which paths to compile per environment
  def elixirc_paths(:test), do: ["lib", "test/support"]
  def elixirc_paths(_), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ecto_sql, "~> 3.10"},
      # Optional backends for Casbin.Watcher (multi-instance policy sync):
      # redix for the Redis pub/sub watcher, postgrex for the Postgres
      # LISTEN/NOTIFY watcher, jason as JSON codec on Elixir < 1.18.
      {:redix, "~> 1.5", optional: true},
      {:postgrex, ">= 0.0.0", optional: true},
      {:jason, "~> 1.4", optional: true},
      {:benchee, "~> 1.3", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:git_hooks, "~> 0.7.3", only: [:dev], runtime: false},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp description() do
    "Casbin-Ex is a powerful and efficient open-source access control library for Elixir projects."
  end

  defp package() do
    [
      name: "casbin",
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE),
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => "https://github.com/casbin/casbin-ex",
        "Homepage" => "https://casbin.org",
        "Docs" => "https://casbin.org/docs/overview"
      }
    ]
  end
end
