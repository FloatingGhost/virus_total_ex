# VirusTotal

A set of bindings to VirusTotal's private API

Implements all endpoints as listed by the [API Docs](https://www.virustotal.com/en/documentation/private-api/)

Example Usage

```elixir
iex> client = VirusTotal.Client.new(my_api_key)
iex> VirusTotal.file_report(client, "7bf5623f0a10dfa148a35bebd899b7758612f1693d2a9910f716cf15a921a76a")
{:ok, %{
   "ITW_urls" => ["https://chiru.no/u/rensenware.exe",
    "http://chiru.no/u/rensenware.exe",
    "http://koakuma.de/rato/Rensenware.exe"],
   "additional_info" => %{...},
   ...
}}
```

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `virus_total` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:virus_total_ex, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/virus_total](https://hexdocs.pm/virus_total_ex).

