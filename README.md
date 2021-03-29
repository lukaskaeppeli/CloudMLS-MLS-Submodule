MLS-TS
======

Test implementation of [Messaging Layer
Security](https://messaginglayersecurity.rocks/) in TypeScript.

**Warning:** the (current) goal of this project is *NOT* to be secure, but to
try to produce an implementation of MLS that can be used for testing ideas
around MLS.  For example, secrets may not be properly purged from memory when
they should be, and no effort was made in auditing the libraries that this
depends on.

This project might turn into a secure implementation in the future, but it
should not be relied on for security at the present time.

In addition, this implementation does not attempt to be efficient in any way,
with respect to both time and memory usage.

Status
------

Targetting draft-11

- [-] HPKE (done, but older version)
  - KEM
    - [X] DHKEM(P256, HKDF-SHA256)
    - [X] DHKEM(P384, HKDF-SHA384)
    - [X] DHKEM(P521, HKDF-SHA512)
    - [X] DHKEM(X25519, HKDF-SHA256)
    - [ ] DHKEM(X448, HKDF-SHA256)
  - KDF
    - [X] HKDF-SHA256
    - [X] HKDF-SHA384
    - [X] HKDF-SHA512
  - AEAD
    - [X] AES-128-GCM
    - [X] AES-256-GCM
    - [X] ChaCha20-Poly1305
- Cipher suite
  - [X] DHKEMX25519_AES128GCM_SHA256_ED25519
  - [ ] DHKEMP256_AES128GCM_SHA256_P256
  - [ ] DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
  - [ ] DHKEMX448_AES256GCM_SHA512_Ed448
  - [ ] DHKEMP521_AES256GCM_SHA512_P521
  - [ ] DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
- Credentials
  - [X] basic credential
  - [ ] X509 credential
- [X] KeyPackage
- Extensions
  - [X] Capabilities
  - [ ] Lifetime
  - [ ] Key ID
  - [X] Parent Hash
  - [X] Ratchet Tree
- [-] Key schedule (older version)
- Ratchet tree
  - [-] Tree hash calculation/verification (partially implemented?)
  - [-] Parent hash calculation/verification (partially implemented?)
  - [-] Add (partially implemented?)
  - [-] Remove (partially implemented?)
  - [-] Update (partially implemented?)
  - [X] UpdatePath
- Group operations
  - [X] Create new group
  - [X] Create group from invite
  - [ ] Create commit and update group
  - [ ] Update group based on received commit
