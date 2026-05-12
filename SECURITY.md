# Security Policy — @commandlayer/runtime-core

## Scope

This package implements Ed25519 signing and verification for CommandLayer protocol
receipts. It is a cryptographic library. Security issues here can affect the trust
guarantees of every receipt produced or verified in the CommandLayer ecosystem.

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Email: security@commandlayer.org

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Whether you have a proposed fix

You will receive an acknowledgment within 48 hours.

## Known Limitations

### No Key Revocation

ENS text records (`cl.sig.pub`) have no expiration or revocation mechanism.
If a signing key is compromised:
- All receipts signed with the compromised key remain verifiable
- The key owner must rotate the ENS `cl.sig.pub` record
- Historical receipts signed before rotation cannot be invalidated

**Mitigation**: Receipts include a `timestamp` field. Consumers can reject receipts
with timestamps before a known compromise date as a matter of policy.

A formal revocation mechanism (`cl.sig.expires`) is planned for v1.2.0.

### ENS Trust Model

Receipt verification trusts the public key published at the signer's ENS name.
This means:
- You trust the ENS name resolution chain (ENS contracts on Ethereum mainnet)
- You trust the ENS name owner to not rotate their key maliciously
- A compromised ENS name owner account can publish fraudulent keys

### Signing Message

The protocol signing message is raw UTF-8 bytes of `canonicalize(receipt.receipt)`.
This is documented in `PROTOCOL.md` and enforced in CI. Any change to the signing
message requires a protocol version bump.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | ✅ Yes    |
| 1.0.x   | ❌ No (breaking signing message issue) |

## Disclosure Policy

- Vulnerabilities are fixed in main and released as a patch version
- Downstream repos are notified before public disclosure
- Public disclosure occurs after all downstream repos have updated
