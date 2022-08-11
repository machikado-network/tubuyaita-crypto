use ed25519_dalek::{self as ed25519, Sha512, Digest};
use ed25519_dalek::Verifier;

#[rustler::nif]
fn verify(message: String, public_key: String, sign: String) -> bool {
    let mut hasher = Sha512::new();
    hasher.update(message.as_bytes());
    let public_key = ed25519::PublicKey::from_bytes(hex::decode(public_key).unwrap().as_slice()).unwrap();
    let signature = ed25519::Signature::from_bytes(hex::decode(sign).unwrap().as_slice()).unwrap();
    public_key.verify(&hasher.finalize(), &signature).is_ok()
}

#[rustler::nif]
fn hash(message: String) -> String {
    let mut hasher = Sha512::new();
    hasher.update(message.as_bytes());
    hex::encode(hasher.finalize())
}

rustler::init!("Elixir.Tubuyaita.Crypto", [verify]);
