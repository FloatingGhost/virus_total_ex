defmodule VirusTotal.MixProject do
  use Mix.Project

  def project do
    [
      app: :virus_total_ex,
      version: "0.1.0",
      elixir: "~> 1.8",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "A set of bindings to VirusTotal's private API",
      package: package()
    ]
  end

  defp package do
    [
      maintainers: ["FloatingGhost"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/FloatingGhost/virus_total_ex",
        "API documentation" => "https://www.virustotal.com/en/documentation/private-api/"
      }
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:tesla, "~> 1.2.0"},
      {:hackney, "~> 1.15.1"},
      {:jason, "~> 1.1.0"},
      {:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end
end
