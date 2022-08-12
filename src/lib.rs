use ed25519_dalek::{self as ed25519, Sha512, Digest, Keypair};
use ed25519_dalek::Verifier;
use rand::rngs::OsRng;

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

#[rustler::nif]
fn generate_keypair() -> (String, String) {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    (String::from_utf8_lossy(keypair.secret.as_bytes()).to_string(), String::from_utf8_lossy(keypair.public.as_bytes()).to_string())
}

// fn sign(message: String, secret_key: rustler::Binary) -> rustler::Binary {
//
// }

rustler::init!("Elixir.Tubuyaita.Crypto", [verify, hash, generate_keypair]);
