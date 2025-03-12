Part1 Verification of Email -> Join Merkle Tree (id: derived from email address, secret: derived from VOPRF)

Server Store:

- root
- path
- email_domain
- threshold

VOPRF:

- hash_email(nonce) - prevent replay register

Part2 Voting with Merkle Tree (root, path, index), Vote

- attestation -> vote in plain text
- nullifier -> prevent double voting

Part3 Output All the Votes (aggregated)

Server API:

- get_info_org() -> Field
- gen_key_voprf() -> Field
