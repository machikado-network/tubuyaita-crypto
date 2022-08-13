use ed25519_dalek::Verifier;
use ed25519_dalek::{Digest, Keypair, PublicKey, Sha512, Signature, Signer};
use rand::rngs::OsRng;
use rustler::{Binary, Env, OwnedBinary};

#[rustler::nif]
fn verify_message(message: String, public_key: String, signature: String) -> bool {
    let mut hasher = Sha512::new();
    hasher.update(message.as_bytes());
    let public_key = PublicKey::from_bytes(hex::decode(public_key).unwrap().as_slice()).unwrap();
    let signature = Signature::from_bytes(hex::decode(signature).unwrap().as_slice()).unwrap();
    public_key.verify(&hasher.finalize(), &signature).is_ok()
}

#[rustler::nif]
fn verify<'a>(message: Binary<'a>, public_key: Binary<'a>, signature: Binary<'a>) -> bool {
    let public_key = PublicKey::from_bytes(public_key.as_slice()).unwrap();
    let signature = Signature::from_bytes(signature.as_slice()).unwrap();
    public_key.verify(message.as_slice(), &signature).is_ok()
}

#[rustler::nif]
fn hash(env: Env<'_>, message: String) -> Binary<'_> {
    let mut hasher = Sha512::new();
    hasher.update(message.as_bytes());

    let mut bin = OwnedBinary::new(64).unwrap();
    bin.as_mut_slice().copy_from_slice(&hasher.finalize());
    Binary::from_owned(bin, env)
}

#[rustler::nif]
fn generate_keypair(env: Env<'_>) -> (Binary<'_>, Binary<'_>) {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let mut secret = OwnedBinary::new(32).unwrap();
    let mut public = OwnedBinary::new(32).unwrap();
    secret
        .as_mut_slice()
        .copy_from_slice(keypair.secret.as_ref());
    public
        .as_mut_slice()
        .copy_from_slice(keypair.public.as_ref());
    (
        Binary::from_owned(secret, env),
        Binary::from_owned(public, env),
    )
}

#[rustler::nif]
fn sign<'a>(
    env: Env<'a>,
    message: String,
    secret_key: Binary<'a>,
    public_key: Binary<'a>,
) -> Binary<'a> {
    let mut secret = secret_key.to_vec();
    secret.append(&mut public_key.to_vec());
    let keypair = Keypair::from_bytes(secret.as_slice()).expect("Failed to create keypair");
    let signature = keypair.sign(message.as_bytes());
    let mut bin = OwnedBinary::new(64).unwrap();
    bin.as_mut_slice().copy_from_slice(signature.as_ref());
    Binary::from_owned(bin, env)
}

#[rustler::nif]
fn from_hex(env: Env<'_>, hex_string: String) -> Binary<'_> {
    let output = hex::decode(hex_string).expect("Failed to decode");
    let mut bin = OwnedBinary::new(output.len()).unwrap();
    bin.as_mut_slice().copy_from_slice(output.as_slice());
    Binary::from_owned(bin, env)
}

#[rustler::nif]
fn to_hex(bin: Binary<'_>) -> String {
    hex::encode(bin.as_slice())
}

rustler::init!(
    "Elixir.Tubuyaita.Crypto",
    [
        verify_message,
        verify,
        hash,
        generate_keypair,
        sign,
        from_hex,
        to_hex
    ]
);
