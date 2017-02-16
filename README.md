# hlin

> Warning! This software is highly experimental and is in no way intended to be
> used for any sensitve or production data.

Securely share secrets.

## Why is this good?

* Allow key rotation independently of secret rotation
* Allow secret rotation independently of key rotation
* Create cryptographically secure data access mechanisms
* Create policies on secrets (not implemented yet)

## How does it work?

`hlin`'s cryptographic protocol works on a higher level as follows:

* Choose plaintext
* Choose participants
* Choose threshold
* Generate random key for use in symmetric encryption
* Encrypt plaintext with previously chosen symmetric key
* Split symmetric key in # of participants + 1 shares using Shamir's Secret
  Sharing with the chosen threshold
* Take one share as the public share, encrypt the others with the participants
  public key

The encrypted secret is made up of the symmetric ciphertext, a public share and
\# of participants encrypted private shares.

When decrypting the following happens:

* Decrypt private shares
* Combine public and private shares to reconstruct the symmetric key
* Decrypt the symmetric ciphertext

Both operations can be successfully performed without exchanging any data with
another participant, when the chosen treshold is 2. For thresholds larger than
2, `n` (`threshold - 2`) additional participants need to decrypt their share
and encrypt it with the participant wanting access to the plaintext.

## Roadmap

The current state allows all of the above except for the last paragraph, as a
secure way communication is required for it.

This software is highly experimental and at this point is in no way intended to
be used in a production environment or for sensitive data.

