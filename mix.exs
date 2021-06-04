defmodule ExPcap.Mixfile do
  use Mix.Project

  @version "0.1.0"
  @github_url "https://github.com/membraneframework/ex_pcap"

  def project do
    [
      app: :ex_pcap,
      version: @version,
      elixir: "~> 1.7",
      name: "expcap",
      source_url: "https://github.com/membraneframework/ex_pcap",
      description: "PCAP library",
      package: package(),
      deps: deps(),
      docs: docs(),
      escript: escript()
    ]
  end

  def escript do
    [main_module: ExPcap.CLI]
  end

  def application do
    [applications: [:logger]]
  end

  defp deps do
    [
      {:pkt, "~> 0.5.0"},
      {:earmark, "~> 1.0", only: :dev},
      {:ex_doc, "~> 0.24.2", only: :dev}
    ]
  end

  defp docs do
    [
      main: "ExPcap",
      extras: ["README.md"],
      source_ref: "v#{@version}"
    ]
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README*"],
      contributors: ["Bryan Weber", "Jakub Hajto"],
      licenses: ["Apache 2.0"],
      links: %{
        "GitHub" => @github_url,
        "Membrane Framework Homepage" => "https://membraneframework.org"
      }
    ]
  end
end
