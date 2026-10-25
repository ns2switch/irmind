use irmind_app::SignerBackend;
use irmind_domain::Actor;

fn leak(backend: &dyn SignerBackend) {
    let signer = backend.load(Actor::Analyst).unwrap();
    let _private = signer.private_key();
}

fn main() {}
