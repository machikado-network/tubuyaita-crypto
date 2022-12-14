defmodule Tubuyaita.Crypto do
  @moduledoc false
  use Rustler,
      otp_app: :tubuyaita_crypto,
      crate: :tubuyaita_crypto,
      path: "../"

  @doc """
    Tubyuaita.Message.Message用の、hexでencodeされたものをverifyする関数
  """
  @spec verify_message(String.t(), String.t(), String.t()) :: boolean()
  def verify_message(_message, _public_key, _sign), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  verify binary message with public key and sign
  """
  @spec verify(binary(), binary(), binary()) :: boolean()
  def verify(_message, _public_key, _sign), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  hash the message.
  """
  @spec hash(String.t()) :: binary()
  def hash(_message), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
    Returns {SecretKey, PublicKey}.
  """
  @spec generate_keypair() :: {binary(), binary()}
  def generate_keypair(), do: :erlang.nif_error(:nif_not_loaded)

  @spec sign(binary(), binary(), binary()) :: {:ok, binary()} | {:error, keyword()}
  def sign(_message, _secret_key, _public_key), do: :erlang.nif_error(:nif_not_loaded)

  @spec from_hex(String.t()) :: {:ok, binary()} | {:error, keyword()}
  def from_hex(_message), do: :erlang.nif_error(:nif_not_loaded)

  @spec try_from_hex(String.t()) :: binary()
  def try_from_hex(_message), do: :erlang.nif_error(:nif_not_loaded)

  @spec to_hex(binary()) :: String.t()
  def to_hex(_binary), do: :erlang.nif_error(:nif_not_loaded)

end
