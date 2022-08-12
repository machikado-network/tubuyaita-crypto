defmodule TubuyaitaCryptoTest do
  use ExUnit.Case
  doctest TubuyaitaCrypto

  test "greets the world" do
    assert TubuyaitaCrypto.hello() == :world
  end

  test "generate keypair" do
    {secret, public} = Tubuyaita.Crypto.generate_keypair()
    assert byte_size(secret) == 32
    assert byte_size(public) == 32
  end

  test "sign" do
    {secret, public} = Tubuyaita.Crypto.generate_keypair()
    r = Tubuyaita.Crypto.sign("abc", secret, public)
    assert Tubuyaita.Crypto.verify("abc", public, r)
  end
end
