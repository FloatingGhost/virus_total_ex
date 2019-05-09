defmodule VirusTotal.Client do
  @moduledoc """
  A client for interacting with virustotal
  """

  use Tesla

  @adapter {
    Tesla.Adapter.Hackney,
    [pool: :virustotal]
  }

  @doc """
  Create a VT client with the API listed in config

  Uses :virustotal -> :api_key
  """
  def new do
    Application.get_env(:virustotal, :api_key)
    |> new()
  end

  @doc """
  Create a VT client with a custom API key. Can be given a custom adapter
  if required

      iex> new("my_apikey")
      %Tesla.Client{...}

      iex> new("my_apikey", adapter: {Tesla.Adapter.Hackney, [pool: :virustotal]})
      %Tesla.Client{...}
  """
  def new(apikey, opts \\ []) do
    middlware = [
      {Tesla.Middleware.BaseUrl, "https://www.virustotal.com/"},
      Tesla.Middleware.JSON,
      {Tesla.Middleware.Retry, delay: 500, max_retries: 5},
      {Tesla.Middleware.Timeout, timeout: 10_000},
      {Tesla.Middleware.Query, apikey: apikey},
      Tesla.Middleware.FollowRedirects
    ]

    adapter = Keyword.get(opts, :adapter, @adapter)
    Tesla.client(middlware, adapter)
  end
end
