# snarkvm-console-account

[![Crates.io](https://img.shields.io/crates/v/snarkvm-console-account.svg?color=neon)](https://crates.io/crates/snarkvm-console-account)
[![Authors](https://img.shields.io/badge/authors-Aleo-orange.svg)](https://aleo.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.md)

## Account keys

In the formulas below, `G` is the generator `GENERATOR_G` of the Edwards BLS12 group.
`Network::new_bases` derives it by hashing `"AleoAccountEncryptionAndSignatureScheme0"` to the curve.
`HashToScalar` is a Poseidon hash whose output is truncated into the scalar field.
The suffix `_psd2`, `_psd4` or `_psd8` names the Poseidon rate.
`domain(s)` is the string `s` as a field element (`Field::new_domain_separator`).
`.x` is the x-coordinate of a point.

An account derives its keys from a random field element `seed`:

- `PrivateKey`: `sk_sig = HashToScalar_psd2(domain("AleoAccountSignatureSecretKey0"), seed)` and `r_sig = HashToScalar_psd2(domain("AleoAccountSignatureRandomizer0.0"), seed)`.
- `ComputeKey`: `pk_sig = sk_sig·G`, `pr_sig = r_sig·G` and `sk_prf = HashToScalar_psd4(pk_sig.x, pr_sig.x)`.
- `Address`: `pk_sig + pr_sig + sk_prf·G`.
- `ViewKey`: `sk_sig + r_sig + sk_prf`. So `address = view_key·G`.

A compute key lets a party compute for an account without its private key. A view key lets a party decrypt the account's records.

## Signatures

`Signature` is a Schnorr signature over a message of field elements.
It holds `(challenge, response, compute_key)`.

To sign a message `m` with `Signature::sign`:

1. Reject `m` if it has more than `MAX_DATA_SIZE_IN_FIELDS` elements.
2. Reject `m` if `m[1] == hash_psd2(m[0])`. A request signature has this form, so a plain signature can never pass as one.
3. Sample a random scalar `nonce`, and compute `g_r = nonce·G`.
4. Compute `challenge = HashToScalar_psd8(g_r.x, pk_sig.x, pr_sig.x, address.x, m)`.
5. Compute `response = nonce - challenge·sk_sig`.

To verify a signature for `address` and `m` with `Signature::verify`:

1. Reject `m` if it has more than `MAX_DATA_SIZE_IN_FIELDS` elements.
2. Compute `g_r = response·G + challenge·pk_sig`. For a valid signature, this is `nonce·G`.
3. Compute the challenge again over the same inputs, and compare it with `challenge`.
4. Derive the address from `compute_key`, and compare it with `address`.

The signature carries the compute key, so the verifier gets `pk_sig` and `pr_sig` from the signature itself.
Step 4 binds them to the address.

`Signature::sign_bytes` and `sign_bits` pack the message bits into field elements and then sign them.
`circuit/account` has the circuit equivalent of `Signature::verify`.

A Poseidon hash absorbs `[poseidon_domain, len(input), 0, …, 0, input]`, padded with zeros to the sponge rate before the input.
`poseidon_domain` is the hash's own setup domain, for example `"AleoPoseidon8"` for `psd8`.
So the hash includes the message length.
