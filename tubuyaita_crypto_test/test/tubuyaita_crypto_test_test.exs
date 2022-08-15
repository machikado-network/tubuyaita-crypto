defmodule TubuyaitaCryptoTest do
  use ExUnit.Case
  doctest TubuyaitaCrypto

  test "greets the world" do
    assert TubuyaitaCrypto.hello() == :world
  end

  test "verify" do
    {secret, public} = Tubuyaita.Crypto.generate_keypair()
    {:ok, r} = Tubuyaita.Crypto.sign("abc", secret, public)
    assert Tubuyaita.Crypto.verify("abc", public, r)
  end

  test "verify fail" do
    {secret, public} = Tubuyaita.Crypto.generate_keypair()
    {:ok, r} = Tubuyaita.Crypto.sign("abc", secret, public)

    # invalid message
    assert Tubuyaita.Crypto.verify("abcde", public, r) == false

    # invalid signature
    assert Tubuyaita.Crypto.verify("abcde", public, <<1, 2, 3>>) == false

    # invalid public key
    assert Tubuyaita.Crypto.verify("abcde", <<1, 2, 3>>, r) == false
  end

  test "hash test" do
    assert Tubuyaita.Crypto.hash("abc") ==
       <<221, 175, 53, 161, 147, 97, 122, 186, 204, 65, 115, 73, 174, 32, 65, 49, 18,
       230, 250, 78, 137, 169, 126, 162, 10, 158, 238, 230, 75, 85, 211, 154, 33,
       146, 153, 42, 39, 79, 193, 168, 54, 186, 60, 35, 163, 254, 235, 189, 69, 77,
       68, 35, 100, 60, 232, 14, 42, 154, 201, 79, 165, 76, 164, 159>>
  end

  test "generate keypair" do
    {secret, public} = Tubuyaita.Crypto.generate_keypair()
    assert byte_size(secret) == 32
    assert byte_size(public) == 32
  end

  test "sign" do
    {secret, public} = Tubuyaita.Crypto.generate_keypair()
    {:ok, r} = Tubuyaita.Crypto.sign("abc", secret, public)
    assert Tubuyaita.Crypto.verify("abc", public, r)
  end

  test "sign fail" do
    {:error, :invalid_keypair} = Tubuyaita.Crypto.sign("abc", "", "")
  end

  test "convert string to hex" do
    assert Tubuyaita.Crypto.to_hex(<<1, 2, 3>>) == "010203"
  end

  test "convert hex to string" do
    assert Tubuyaita.Crypto.from_hex("010203") == {:ok, <<1, 2, 3>>}
  end

  test "convert hex fail" do
    assert Tubuyaita.Crypto.from_hex("010203PP") == {:error, :invalid_hex_string}
  end

  test "hash and sign" do
    {s, p} = Tubuyaita.Crypto.generate_keypair()
    Tubuyaita.Crypto.sign(Tubuyaita.Crypto.hash("abc"), s, p)
  end
end
