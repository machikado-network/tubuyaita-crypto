defmodule TubuyaitaCryptoTest do
  use ExUnit.Case
  doctest TubuyaitaCrypto

  test "greets the world" do
    assert TubuyaitaCrypto.hello() == :world
  end

  test "generate keypair" do
    {secret, public} = Tubuyaita.Crypto.generate_keypair()
    assert String.length(secret) == 32
    assert String.length(public) == 32
  end
end
