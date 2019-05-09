defmodule VirusTotalTest do
  use ExUnit.Case
  doctest VirusTotal

  test "greets the world" do
    assert VirusTotal.hello() == :world
  end
end
