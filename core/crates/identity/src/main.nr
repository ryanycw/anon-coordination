use std::{collections::bounded_vec::BoundedVec, hash::pedersen_hash};
use zkemail::{
    dkim::RSAPubkey, headers::email_address::get_email_address, KEY_LIMBS_2048,
    MAX_EMAIL_ADDRESS_LENGTH, Sequence,
};

global MAX_DOMAIN_LENGTH: u32 = 64;
global MAX_EMAIL_HEADER_LENGTH: u32 = 512;

/**
 * Verify an arbitrary email signed by a 2048-bit RSA DKIM signature and extract sender and recipient addresses
 * @dev example of only constraining access to the header too
 *
 * @param header - The email header, 0-padded at end to the MAX_EMAIL_HEADER_LENGTH
 * @param pubkey - The DKIM RSA Public Key modulus and reduction parameter
 * @param signature - The DKIM RSA Signature
 * @param org_id - The organization ID
 * @param to_header_sequence - The index and length of the "To" header field
 * @param to_address_sequence - The index and length of the "To" email address
 * @return - 
 *         0: Pedersen hash of DKIM public key (root of trust)
 *         1: Pedersen hash of DKIM signature (email nullifier)
 */
fn main(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    pubkey: RSAPubkey<KEY_LIMBS_2048>,
    signature: [Field; KEY_LIMBS_2048],
    domain: pub BoundedVec<u8, MAX_DOMAIN_LENGTH>,
    to_header_sequence: Sequence,
    to_address_sequence: Sequence,
    ) -> pub ([Field; 2], BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH>) {
    // check the body and header lengths are within bounds
    assert(header.len() <= MAX_EMAIL_HEADER_LENGTH);

    // verify the dkim signature over the header
    pubkey.verify_dkim_signature(header, signature);

    // extract to email addresses
    let to = comptime { "to".as_bytes() };
    // 16k gate cost? has to be able to be brought down
    let to_address = get_email_address(header, to_header_sequence, to_address_sequence, to);

    // Get domain start_index from email claim - unconstrained, but we verify the domain bytes below
    let domain_start_index = unsafe { get_domain_start_index_in_email(to_address) };

    // Verify domain passed is present in the email claim after the @
    assert(to_address.storage()[domain_start_index - 1] == 64, "char before domain is not '@'");
    for i in 0..MAX_DOMAIN_LENGTH {
        assert(to_address.storage()[domain_start_index + i] == domain.storage()[i], "invalid domain");
    }

    // hash the pubkey and signature for the standard outputs
    let email_nullifier = pedersen_hash(signature);
    let standard_out = [pubkey.hash(), email_nullifier];
    (standard_out, to_address)
}

unconstrained fn get_domain_start_index_in_email(email: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH>) -> u32 {
    let mut domain_start_index = 0;
    for i in 0..MAX_EMAIL_ADDRESS_LENGTH {
        if email.storage()[i] == ("@".as_bytes())[0] {
            domain_start_index = i + 1;
            break;
        }
    }

    domain_start_index
}