use ed25519_dalek::Verifier;
use ed25519_dalek::{Digest, Keypair, PublicKey, Sha512, Signature, Signer};
use rand::rngs::OsRng;
use rustler::{Atom, Binary, Env, Error, OwnedBinary};

mod atoms {
    rustler::atoms! {
        ok,
        error,
        invalid_keypair,
        invalid_hex_string,
    }
}

#[rustler::nif]
fn verify_message(message: String, public_key: String, signature: String) -> bool {
    let mut hasher = Sha512::new();
    hasher.update(message.as_bytes());

    match (hex::decode(public_key), hex::decode(signature)) {
        (Ok(public_key), Ok(signature)) => {
            if let Ok(public_key) = PublicKey::from_bytes(public_key.as_slice()) {
                if let Ok(signature) = Signature::from_bytes(signature.as_slice()) {
                    return public_key.verify(&hasher.finalize(), &signature).is_ok();
                }
            }
            false
        }
        _ => false
    }
}

#[rustler::nif]
fn verify<'a>(message: Binary<'a>, public_key: Binary<'a>, signature: Binary<'a>) -> bool {
    if let Ok(public_key) = PublicKey::from_bytes(public_key.as_slice()) {
        if let Ok(signature) = Signature::from_bytes(signature.as_slice()) {
            return public_key.verify(message.as_slice(), &signature).is_ok();
        }
    }
    false
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
    message: Binary<'a>,
    secret_key: Binary<'a>,
    public_key: Binary<'a>,
) -> Result<(Atom, Binary<'a>), Error> {
    let mut secret = secret_key.to_vec();
    secret.append(&mut public_key.to_vec());
    if let Ok(keypair) = Keypair::from_bytes(secret.as_slice()) {
        let signature = keypair.sign(message.as_slice());
        let mut bin = OwnedBinary::new(64).unwrap();
        bin.as_mut_slice().copy_from_slice(signature.as_ref());
        Ok((atoms::ok(), Binary::from_owned(bin, env)))
    } else {
        Err(Error::Term(Box::new(atoms::invalid_keypair())))
    }
}

#[rustler::nif]
fn from_hex(env: Env<'_>, hex_string: String) -> Result<(Atom, Binary<'_>), Error> {
    direct_from_hex(env, hex_string)
}

#[rustler::nif]
fn try_from_hex(env: Env<'_>, hex_string: String) -> Binary<'_> {
    direct_from_hex(env, hex_string).unwrap().1
}

fn direct_from_hex(env: Env<'_>, hex_string: String) -> Result<(Atom, Binary<'_>), Error> {
    if let Ok(output) = hex::decode(hex_string) {
        let mut bin = OwnedBinary::new(output.len()).unwrap();
        bin.as_mut_slice().copy_from_slice(output.as_slice());
        Ok((atoms::ok(), Binary::from_owned(bin, env)))
    } else {
        Err(Error::Term(Box::new(atoms::invalid_hex_string())))
    }
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
        to_hex,
        try_from_hex,
    ]
);
