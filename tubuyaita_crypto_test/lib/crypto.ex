defmodule Tubuyaita.Crypto do
  @moduledoc false
  use Rustler,
      otp_app: :tubuyaita_crypto,
      crate: :tubuyaita_crypto,
      path: "../"

  @doc """
    Tubyuaita.Message.Message用の、hexでencodeされたものをverifyする関数
  """
  @spec verify_message(String.t(), String.t(), String.t()) :: Bool.t()
  def verify_message(_message, _public_key, _sign), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  verify binary message with public key and sign
  """
  @spec verify(String.t(), String.t(), String.t()) :: Bool.t()
  def verify(_message, _public_key, _sign), do: :erlang.nif_error(:nif_not_loaded)

  @spec hash(String.t()) :: String.t()
  def hash(_message), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
    Returns {SecretKey, PublicKey}.
  """
  @spec generate_keypair() :: {String.t(), String.t()}
  def generate_keypair(), do: :erlang.nif_error(:nif_not_loaded)

  @spec sign(String.t(), String.t(), String.t()) :: String.t()
  def sign(_message, _secret_key, _public_key), do: :erlang.nif_error(:nif_not_loaded)

end
