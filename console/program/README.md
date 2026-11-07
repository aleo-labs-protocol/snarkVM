# snarkvm-console-program

[![Crates.io](https://img.shields.io/crates/v/snarkvm-console-program.svg?color=neon)](https://crates.io/crates/snarkvm-console-program)
[![Authors](https://img.shields.io/badge/authors-Aleo-orange.svg)](https://aleo.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.md)

## Record encryption

A record encrypts its private parts for its owner.
The encryption uses a Diffie-Hellman key and a Poseidon keystream.
The notation is the same as in `console/account/README.md`.

### Keys

A record that a transition outputs has an encryption randomizer, derived from the transition view key `tvk`:

- `randomizer = HashToScalar(tvk, locator)`, where `locator` is the output register's locator.
- `nonce = randomizer·G`. The record stores `nonce` in the clear, and `Record::encrypt` rejects a randomizer that does not match it.

The record view key is a shared secret between the transition and the owner:

- The encryptor computes `record_view_key = (randomizer·owner).x`.
- The owner computes `record_view_key = (view_key·nonce).x`. Because `owner = view_key·G`, both give the same key.

### Encryption

`Record::encrypt` makes the keystream `hash_many_psd8([domain("AleoSymmetricEncryption0"), record_view_key], n)`.
Here `n` is the number of field elements that the private parts of the record need.
Then it adds one keystream element to each such field element, in order:

1. a private owner, as `owner.x + k_0`;
2. each private entry, as its plaintext field elements plus the next keystream elements.

Constant and public entries, and a public owner, stay in the clear and use no keystream elements.
`Plaintext::to_fields` encodes a plaintext as its little-endian bits, one final `1` bit, and the bits packed into field elements.

### Decryption

`Record::decrypt` computes the record view key from the view key and the nonce, makes the same keystream, and subtracts it.
Then it checks that the decrypted owner is the view key's address.
Decryption exists only in console. The circuit only encrypts.

### Binding to the transition

The encryption does not prove by itself that the transition encrypted the record for its owner.
The transition's circuit does the same encryption (see `Response::from_outputs` in `circuit/program`).
It outputs `BHP1024` of the encrypted record as the record's checksum, beside the record's commitment.
The proof takes the commitment and the checksum as public inputs.
`Output::verify` in `ledger/block` checks that the record ciphertext in the transition hashes to the checksum.
So a valid transition shows that its record ciphertext is the honest encryption of the committed record.

`Plaintext::encrypt` and `Ciphertext::decrypt` use the same keystream for a plaintext value.
The encryptor's key is `(randomizer·address).x`, and the recipient's key is `(view_key·nonce).x`.
