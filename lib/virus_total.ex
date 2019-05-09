defmodule VirusTotal do
  @moduledoc """
  Documentation for VirusTotal.

  Full API documentation can be found on the
  [official site](https://www.virustotal.com/en/documentation/private-api)

  As a note, this wrapper will convert HTTP-200 responses with a `response_code` of
  0 to errors. Apparently VT considers to be HTTP 200 to be a valid status code for
  "not found". How silly.

  Example usage:

      iex> client = VirusTotal.Client.new(my_api_key)
      iex> {:ok, report} = VirusTotal.file_report(client, "7bf5623f0a10dfa148a35bebd899b7758612f1693d2a9910f716cf15a921a76a")
      {:ok, %{"ITW_urls" => ["https://chiru.no/u/rensenware.exe"], ...}}
  """

  @doc """
  Retrieves a concluded file scan report for a given file.

  Valid parameters:
  - `:allinfo`: if this is specified and set to 1, the call will return additional info.
    This is turned ON by default

      iex> file_report(client, "7bf5623f0a10dfa148a35bebd899b7758612f1693d2a9910f716cf15a921a76a")
      {:ok, %{"ITW_urls" => ["https://chiru.no/u/rensenware.exe"]}}
  """
  def file_report(client, hash, params \\ [allinfo: 1]) do
    params = Keyword.merge(params, resource: hash)

    Tesla.get(client, "/vtapi/v2/file/report", query: params)
    |> parse()
  end

  @doc """
  Allows you to rescan files present in VirusTotal's file store
  without having to resubmit them

      iex> rescan_file(client, some_hash)
      {:ok, %{"scan_id" => "something"}}

  Valid parameters:
  - `:date`: Date in %Y%m%d%H%M%S format (example: 20120725170000)
          in which the rescan should be performed.
          If not specified the rescan will be performed immediately.
  - `:period`: Periodicity (in days) with which the file should be rescanned.
            If this argument is provided the file will be rescanned periodically
            every `period` days, if not, the rescan is performed once and not repeated again.
  - `:repeat`: Used in conjunction with `period` to specify the number of times the file
            should be rescanned.
            If this argument is provided the file will be
            rescanned the given amount of times in coherence with the chosen periodicity,
            if not, the file will be rescanned indefinitely.
  - `:notify_url`: A URL to which a POST notification should be sent when the rescan finishes.
  - `:notify_changes_only`: Used in conjunction with notify_url.
                         Indicates if POST notifications should only be sent if the
                         scan results differ from the previous one.
  """
  def rescan_file(client, resource, params \\ []) do
    params = Keyword.merge(params, resource: resource)

    Tesla.post(client, "/vtapi/v2/file/rescan", query: params)
    |> parse()
  end

  @doc """
  Deletes a scheduled file rescan task. The file rescan api allows you to schedule
  periodic scans of a file, this API call tells VirusTotal to stop rescanning
  a file that you have previously enqueued for recurrent scanning.
  """
  def delete_rescan(client, resource) do
    Tesla.post(client, "/vtapi/v2/file/rescan/delete", query: [resource: resource])
    |> parse()
  end

  @doc """
  VirusTotal runs a distributed setup of Cuckoo sandbox machines that execute the files
  they receive.
  Execution is attempted only once, upon first submission to VirusTotal,
  and only Portable Executables under 10MB in size are ran.
  The execution of files is a best effort process, hence,
  there are no guarantees about a report being generated for a given file in the dataset.
  """
  def file_behaviour(client, hash) do
    Tesla.get(client, "/vtapi/v2/hash/behaviour", query: [hash: hash])
    |> parse()
  end

  @doc """
  Files that are successfully executed may communicate with certain network resources,
  all this communication is recorded in a network traffic dump (pcap file).
  This API allows you to retrieve the network traffic dump generated during the
  file's execution.
  """
  def file_network_traffic(client, hash) do
    Tesla.get(client, "/vtapi/v2/hash/network-traffic", query: [hash: hash])
    |> parse()
  end

  @doc """
  Valid params:
  - `:offset`: The offset value returned by a previously issued identical query,
               allows you to paginate over the results.
               If not specified the first 300 matching files sorted according to last
               submission date to VirusTotal in a descending fashion will be returned.
  """
  def file_search(client, query, params \\ %{}) do
    params = Map.merge(params, %{query: query})

    Tesla.post(client, "/vtapi/v2/file/search", params)
    |> parse()
  end

  @doc """
  This API offers a programmatic access to the clustering section of VirusTotal Intelligence

  Valid params:
  - `:date`: A specific day for which we want to access the clustering details,
             example: 2013-09-10.
  """
  def file_clusters(client, date) do
    Tesla.get(client, "/vtapi/v2/file/clusters", query: [date: date])
    |> parse()
  end

  @doc """
  Downloads a file from VirusTotal's store

      iex> file_download(client, "7bf5623f0a10dfa148a35bebd899b7758612f1693d2a9910f716cf15a921a76a")
      {:ok, <<77, 90, 144, ...>>}
  """
  def file_download(client, hash) do
    Tesla.get(client, "/vtapi/v2/file/download", query: [hash: hash])
    |> case do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, other} ->
        {:error, other}

      other ->
        other
    end
  end

  @doc """
  Retrieves a report for a given URL

      iex> url_report(client, "https://yuruyuri.com/")
      {:ok, %{"positives" => 0, ...}}

  """
  def url_report(client, url) do
    Tesla.get(client, "/vtapi/v2/url/report", query: [resource: url])
    |> parse()
  end

  @doc """
  Allows you to submit URLs to be scanned by VirusTotal

      iex> url_scan(client, "https://yuruyuri.com")
      {:ok, %{"scan_id" => ...}}
  """
  def url_scan(client, url) do
    Tesla.post(client, "/vtapi/v2/url/scan", query: [url: url])
    |> parse()
  end

  @doc """
  Retrieves a report on a given IP address
  (including the information recorded by VirusTotal's Passive DNS infrastructure).

      iex> ip_report(client, "8.8.8.8")
      {:ok, %{"asn" => ...}}
  """
  def ip_report(client, ip) do
    Tesla.get(client, "/vtapi/v2/ip-address/report", query: [ip: ip])
    |> parse()
  end

  @doc """
  Retrieves a report on a given domain
  (including the information recorded by VirusTotal's passive DNS infrastructure).
  """
  def domain_report(client, domain) do
    Tesla.get(client, "/vtapi/v2/domain/report", query: [domain: domain])
    |> parse()
  end

  @doc """
  Retrieves all notifications created by VirusTotal's hunting functionality
  """
  def notifications(client) do
    Tesla.get(client, "/intelligence/hunting/notifications-feed/")
    |> case do
      {:ok, %{status: 200, body: body}} ->
        Jason.decode(body)

      {:ok, other} ->
        {:error, other}

      other ->
        other
    end
  end

  def put_comment(client, resource, comment) do
    Tesla.post(client, "/vtapi/v2/comments/put", query: [resource: resource, comment: comment])
    |> parse()
  end

  def get_comments(client, resource, params \\ []) do
    params = Keyword.merge(params, resource: resource)

    Tesla.get(client, "/vtapi/v2/comments/get", query: params)
    |> parse()
  end

  defp parse(response) do
    case response do
      {:ok, %{status: 200, body: %{"response_code" => 1} = body}} ->
        {:ok, body}

      {:ok, env} ->
        {:error, env}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
