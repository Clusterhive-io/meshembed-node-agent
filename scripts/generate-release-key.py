#!/usr/bin/env python3
"""Generate a new ed25519 release-signing keypair.

Run ONCE on a trusted machine (never on CI). Outputs:
  - the private key in hex (64 chars) -- store as the GitHub Actions
    secret MESHEMBED_RELEASE_PRIVKEY_HEX
  - the public key in hex (64 chars) -- paste into install.sh,
    install-mac.sh, install.ps1 as the RELEASE_PUBKEY_HEX constant.

After rotation: the new pubkey only takes effect for releases tagged
AFTER the secret is updated. Old releases stay signed by the old key,
which is fine since their installers are already in operator hands.

The private key never leaves this machine in any usable form.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> None:
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes_raw().hex()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    print("=" * 70)
    print(" MeshEmbed release-signing keypair")
    print("=" * 70)
    print()
    print("PRIVATE KEY (set this as the MESHEMBED_RELEASE_PRIVKEY_HEX")
    print("GitHub Actions secret; ALSO store a copy in 1Password):")
    print()
    print(f"  {priv_hex}")
    print()
    print("PUBLIC KEY (paste this into install.sh, install-mac.sh, install.ps1")
    print("as the RELEASE_PUBKEY_HEX constant; commit those changes):")
    print()
    print(f"  {pub_hex}")
    print()
    print("Next steps:")
    print("  1. Update RELEASE_PUBKEY_HEX in install.{sh,ps1} + install-mac.sh.")
    print("  2. Set the GH Actions secret MESHEMBED_RELEASE_PRIVKEY_HEX.")
    print("  3. Cut a test release and verify the installer accepts it.")


if __name__ == "__main__":
    main()
