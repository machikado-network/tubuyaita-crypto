use ed25519_dalek::{self as ed25519, Sha512, Digest, Keypair};
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::Verifier;
use rand::rngs::OsRng;
use rustler::{Binary, OwnedBinary, Env};

#[rustler::nif]
fn verify(message: String, public_key: String, signature: String) -> bool {
    let mut hasher = Sha512::new();
    hasher.update(message.as_bytes());
    let public_key = ed25519::PublicKey::from_bytes(hex::decode(public_key).unwrap().as_slice()).unwrap();
    let signature = ed25519::Signature::from_bytes(hex::decode(signature).unwrap().as_slice()).unwrap();
    public_key.verify(&hasher.finalize(), &signature).is_ok()
}

#[rustler::nif]
fn hash(message: String) -> String {
    let mut hasher = Sha512::new();
    hasher.update(message.as_bytes());
    hex::encode(hasher.finalize())
}

#[rustler::nif]
fn generate_keypair<'a>(env: Env<'a>) -> (Binary<'a>, Binary<'a>) {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let mut secret = OwnedBinary::new(32).unwrap();
    let mut public = OwnedBinary::new(32).unwrap();
    secret.as_mut_slice().copy_from_slice(keypair.secret.as_ref());
    public.as_mut_slice().copy_from_slice(keypair.public.as_ref());
    (Binary::from_owned(secret, env.clone()), Binary::from_owned(public, env))
}

#[rustler::nif]
fn sign(message: String, secret_key: String) -> String {
    let mut keypair = Keypair::from_bytes(secret_key.as_bytes()).unwrap();
    keypair.sign(message.as_bytes()).to_string()
}


rustler::init!("Elixir.Tubuyaita.Crypto", [verify, hash, generate_keypair, sign]);
