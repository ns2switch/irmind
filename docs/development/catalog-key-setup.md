# Provision the catalog signing key

Maintainer procedure for the [signed catalog contract](https://github.com/ns2switch/irmind/pull/287).
Do this on your own machine, outside any Git checkout. IRMind and the development
agent need only the public key and its ID. Do not send the seed or a private key.
The publishing workflow uses the protected `release` environment in
`ns2switch/irmind-skills`; branch rehearsals use synthetic fixture keys.

## Active production key

Production key registered on 2026-11-17 for IRMind v0.5.4:

```text
public_key=fb2015c83d13fe018e270a7fe73bf7bccfdb622565e30f7ade436637c3b2c25b
key_id=f04daae3f8243ed76452d5f787ea527c8fbec895ca0c91a35f453f6677575e4f
```

The ID is SHA-256 of the 32 raw public bytes. The release accepts only reviewed
compiled keys (at most eight); synthetic keys are confined to test verifiers.
The private seed exists only in the catalog's protected release environment.
IRMind never downloads trust roots or reads a private catalog key.

To rotate, generate a new seed locally, submit only its public key and ID for a
reviewed IRMind release, and coordinate the catalog signer with the compiled list.
A bounded overlap allows an orderly transition. Removing a key also requires an
IRMind release: after removal, indexes signed only by that key are rejected.
A catalog index cannot grant trust to another key. Distribute the new executable
before switching the catalog signer. If a key is compromised, retire it in the
next IRMind release and stop signing with it; an older binary retains its old roots.

## Generate locally

Requires Python 3 and OpenSSL 3. The following creates a new private directory,
writes exactly 64 lowercase hex characters representing a random 32-byte seed,
and prints only the raw public key and its SHA-256 key ID. It refuses to replace
an existing directory or seed. Private DER is passed to OpenSSL over stdin and
is not written to a file or included in command arguments.

```sh
umask 077
python3 - <<'PY'
import hashlib
import os
from pathlib import Path
import secrets
import subprocess

seed = secrets.token_bytes(32)
der = bytes.fromhex("302e020100300506032b657004220420") + seed
result = subprocess.run(
    ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
    input=der, capture_output=True, check=True,
)
prefix = bytes.fromhex("302a300506032b6570032100")
if len(result.stdout) != 44 or not result.stdout.startswith(prefix):
    raise SystemExit("Unexpected Ed25519 public-key encoding")
public = result.stdout[len(prefix):]
key_id = hashlib.sha256(public).hexdigest()
root = Path("catalog-key-material")
root.mkdir(mode=0o700)
fd = os.open(root / "catalog-seed.hex", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="ascii") as output:
    output.write(seed.hex())
(root / "catalog-public.hex").write_text(public.hex() + "\n", encoding="ascii")
(root / "catalog-key-id.txt").write_text(key_id + "\n", encoding="ascii")
print("public_key=" + public.hex())
print("key_id=" + key_id)
PY
```

The seed is not a 64-byte expanded private key and the public key is not a PEM
or DER object: both are raw 32-byte values encoded as 64 lowercase hex characters.
`key_id` hashes the raw public bytes, not their hex text. The DER wrappers follow
[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html); OpenSSL's
[pkey interface](https://docs.openssl.org/3.0/man1/openssl-pkey/) derives the public
key without displaying the private input.

## Protect and upload the seed

In the catalog repository's Settings → Environments, create `release`. Configure
required maintainer review and allow deployments only from selected **tags**
matching `v*`, not branches. The production publishing job must reference this
environment and execute only from an explicitly selected published tag. Synthetic dispatch jobs never request
it. Follow GitHub's [environment configuration](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

Use an environment secret named `CATALOG_ED25519_SEED_HEX`, not a repository or
organization secret. From the directory containing `catalog-key-material`:

```sh
gh secret set CATALOG_ED25519_SEED_HEX --repo ns2switch/irmind-skills --env release < catalog-key-material/catalog-seed.hex
```

The [GitHub CLI command](https://cli.github.com/manual/gh_secret_set) reads the
value from stdin. Retain a protected offline backup according to your key policy;
remove the unencrypted local seed file after provisioning and backup. Do not put
it in Git, chat, shell arguments, logs or release assets.

Provide only the two printed public values for a reviewed change to the catalog's
expected publisher key and IRMind's compiled allowlist. A synthetic fixture key
must never become production trust. Publishing stays unavailable until these
public values and the protected environment are configured. Rotation adds or
removes a compiled public key through an IRMind release; the index cannot install
a new trust root.
