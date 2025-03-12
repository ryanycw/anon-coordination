// In essence this is a ring or hiding signature using zk
fn main(
    nullifier: pub Field,
    root: pub Field,
    attestation: pub Field,
    path: [Field; 10],
    index: Field,
    priv_key: Field,
) {
    // Computes public key as s x G using a private key from the embeded curve (babyJubJub or other)
    let scalar = std::embedded_curve_ops::EmbeddedCurveScalar::from_field(priv_key);
    let point = std::embedded_curve_ops::fixed_base_scalar_mul(scalar);

    // Computes the leaf of the merkle tree using an asigned id and secret
    let id_leaf: Field = std::hash::pedersen_hash([point.x, point.y]);

    // Proves the root in the public input is equal to the the one from the provided path plus leaf
    let proposed_root = std::merkle::compute_merkle_root(id_leaf, index, path);
    assert_eq(proposed_root, root);

    // Finally ensure the hash of the secret plus the attestation
    let proposed_nullifier = std::hash::pedersen_hash([attestation, priv_key]);
    assert_eq(proposed_nullifier, nullifier);
}
