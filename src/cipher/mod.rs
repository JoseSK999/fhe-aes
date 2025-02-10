use crate::{sub_byte, FheRoundKey};
use rayon::prelude::*;
use tfhe::integer::{BooleanBlock, IntegerCiphertext};
use tfhe::integer::{RadixCiphertext, ServerKey};
use tfhe::integer::prelude::ServerKeyDefaultCMux;

struct AesState([RadixCiphertext; 16]);

impl AesState {
    /// Applies the S-box substitution to every byte in the state in parallel.
    fn sub_bytes(&self, sk: &ServerKey) -> Self {
        let new_state: [RadixCiphertext; 16] = self.0
            .par_iter()
            .map(|enc_byte| sub_byte(sk, enc_byte))
            .collect::<Vec<_>>()
            .try_into()
            .expect("Expected exactly 16 elements");
        AesState(new_state)
    }

    /// A simplified ShiftRows implementation using a fixed permutation.
    /// In column‑major order, ShiftRows maps the indices as follows:
    /// [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] →
    /// [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
    fn shift_rows(self) -> Self {
        // Destructure the inner array (consuming self)
        let [s0, s1, s2, s3,
        s4, s5, s6, s7,
        s8, s9, s10, s11,
        s12, s13, s14, s15] = self.0;

        AesState([
            s0,  s5,  s10, s15,
            s4,  s9,  s14, s3,
            s8,  s13, s2,  s7,
            s12, s1,  s6,  s11,
        ])
    }

    /// Applies the AES MixColumns transformation on the state.
    ///
    /// Each column (of 4 bytes) is transformed as follows:
    ///   new0 = (02 • s0) ⊕ (03 • s1) ⊕ s2 ⊕ s3
    ///   new1 = s0 ⊕ (02 • s1) ⊕ (03 • s2) ⊕ s3
    ///   new2 = s0 ⊕ s1 ⊕ (02 • s2) ⊕ (03 • s3)
    ///   new3 = (03 • s0) ⊕ s1 ⊕ s2 ⊕ (02 • s3)
    ///
    /// The multiplication is over GF(2⁸) using the AES irreducible polynomial.
    fn mix_columns(&self, sk: &ServerKey) -> Self {
        // Process each column by extracting 4 consecutive ciphertexts,
        // applying mix_single_column, and then reassembling the state.
        let new_columns: Vec<[RadixCiphertext; 4]> = (0..4)
            .into_par_iter()
            .map(|col| {
                let column = &self.0[col * 4..col * 4 + 4];
                mix_single_column(sk, column.try_into().expect("Slice with 4 elements"))
            })
            .collect();

        let new_state: [RadixCiphertext; 16] = new_columns
            .into_iter()
            .flat_map(|col| col.into_iter())
            .collect::<Vec<_>>()
            .try_into()
            .expect("Expected 16 elements");

        AesState(new_state)
    }

    fn add_round_key(&self, round_key: &[RadixCiphertext; 16], sk: &ServerKey) -> Self {
        // Perform byte-by-byte XOR in parallel between self and the round_key.
        let new_state: [RadixCiphertext; 16] = self.0
            .par_iter()
            .zip(round_key.par_iter())
            .map(|(a, b)| sk.bitxor_parallelized(a, b))
            .collect::<Vec<_>>()
            .try_into()
            .expect("Expected 16 elements");

        AesState(new_state)
    }
}

/// Encrypts a 16-byte plaintext using the provided AES round keys,
/// applying the standard AES-128 round transformations in FHE.
pub fn fhe_aes_encrypt(
    sk: &ServerKey,
    plaintext: [RadixCiphertext; 16],
    round_keys: &[FheRoundKey; 11],
) -> [RadixCiphertext; 16] {
    // Initial round: XOR plaintext with round key 0
    let mut state = AesState(plaintext);
    state = state.add_round_key(&round_keys[0].0, sk);

    // Rounds 1 through 9
    for round in 1..10 {
        state = state.sub_bytes(sk);

        state = state.shift_rows();
        state = state.mix_columns(sk);

        state = state.add_round_key(&round_keys[round].0, sk);
    }

    // Final round (no MixColumns)
    state = state.sub_bytes(sk);
    state = state.shift_rows();
    state = state.add_round_key(&round_keys[10].0, sk);

    state.0
}

// Applies the MixColumns transformation to a single column.
fn mix_single_column(sk: &ServerKey, column: &[RadixCiphertext; 4]) -> [RadixCiphertext; 4] {
    let s0 = &column[0];
    let s1 = &column[1];
    let s2 = &column[2];
    let s3 = &column[3];

    let ((new0, new1), (new2, new3)) = rayon::join(
        || rayon::join(
            || {
                let (g0, g1) = rayon::join(
                    || gf_mul_by_2(sk, s0),
                    || gf_mul_by_3(sk, s1),
                );
                xor4(sk, &g0, &g1, s2, s3)
            },
            || {
                let (g0, g1) = rayon::join(
                    || gf_mul_by_2(sk, s1),
                    || gf_mul_by_3(sk, s2),
                );
                xor4(sk, s0, &g0, &g1, s3)
            },
        ),
        || rayon::join(
            || {
                let (g0, g1) = rayon::join(
                    || gf_mul_by_2(sk, s2),
                    || gf_mul_by_3(sk, s3),
                );
                xor4(sk, s0, s1, &g0, &g1)
            },
            || {
                let (g0, g1) = rayon::join(
                    || gf_mul_by_3(sk, s0),
                    || gf_mul_by_2(sk, s3),
                );
                xor4(sk, &g0, s1, s2, &g1)
            },
        ),
    );

    [new0, new1, new2, new3]
}

// Helper function to compute (A XOR B) XOR (C XOR D)
fn xor4(
    sk: &ServerKey,
    a: &RadixCiphertext,
    b: &RadixCiphertext,
    c: &RadixCiphertext,
    d: &RadixCiphertext,
) -> RadixCiphertext {
    let (ab, cd) = rayon::join(
        || sk.bitxor_parallelized(a, b),
        || sk.bitxor_parallelized(c, d),
    );
    sk.bitxor_parallelized(&ab, &cd)
}

// Helper functions for GF(2⁸) multiplication.
fn gf_mul_by_2(sk: &ServerKey, ct: &RadixCiphertext) -> RadixCiphertext {
    // Compute the left-shift by one bit. This is equivalent to multiplying by 2.
    let (shifted, input_msb_set) = rayon::join(
        || sk.scalar_left_shift_parallelized(ct, 1),
        || is_msb_set(sk, ct),
    );
    // Compute the adjusted value: shifted XOR 0x1B.
    let shifted_reduced = sk.scalar_bitxor_parallelized(&shifted, 0x1B);

    // If the condition is true, select the adjusted value; otherwise, use shifted.
    sk.if_then_else_parallelized(&input_msb_set, &shifted_reduced, &shifted)
}

fn gf_mul_by_3(sk: &ServerKey, ct: &RadixCiphertext) -> RadixCiphertext {
    let mul2 = gf_mul_by_2(sk, ct);
    sk.bitxor_parallelized(&mul2, ct)
}

fn is_msb_set(sk: &ServerKey, enc_byte: &RadixCiphertext) -> BooleanBlock {
    // Last block is the MSB block (blocks are returned in little endian order)
    let mut msb_block = RadixCiphertext::from_blocks(
        vec![enc_byte.blocks().last().unwrap().clone()]
    );
    sk.scalar_right_shift_assign_parallelized(&mut msb_block, 1);

    // If we have 01, bit is set, else if we have 00, it is not
    BooleanBlock::new_unchecked(msb_block.blocks().first().unwrap().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encrypt_block, decrypt_block};
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;
    use tfhe::integer::{ClientKey, IntegerCiphertext};

    #[test]
    fn test_shift_rows_encrypted() {
        let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);

        // Build an initial AES state with encrypted values.
        // The state is in column-major order:
        //   [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ]
        let initial_state: [RadixCiphertext; 16] = std::array::from_fn(|i| {
            ck.encrypt_radix(i as u8, 4)
        });
        let state = AesState(initial_state);

        // Expected plaintext result after ShiftRows:
        // For column-major order, the original matrix is:
        //   [  0   4    8   12 ]
        //   [  1   5    9   13 ]
        //   [  2   6   10   14 ]
        //   [  3   7   11   15 ]
        //
        // After ShiftRows (each row shifted left by its row index):
        //   Row 0: unchanged: [ 0,  4,  8, 12 ]
        //   Row 1: shifted left by 1: [ 5,  9, 13, 1 ]
        //   Row 2: shifted left by 2: [ 10, 14, 2, 6 ]
        //   Row 3: shifted left by 3: [ 15, 3, 7, 11 ]
        // Reassembled in column‑major order, the expected state is:
        let expected: [u8; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

        let shifted_state = state.shift_rows();

        let decrypted = decrypt_block(&ck, &shifted_state.0);
        assert_eq!(
            decrypted,
            expected,
            "ShiftRows did not rearrange the state as expected"
        );
    }

    #[test]
    fn test_little_endian_block_order() {
        let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);

        // 0xE4 (228 in decimal) is 11_10_01_00 in binary
        let num = ck.encrypt_radix(0xE4_u8, 4);

        // Blocks are read in little endian order, so the values must be 0, 1, 2 and 3
        num.blocks().iter().enumerate().for_each(|(i, block)| {
            let val = ck.decrypt_one_block(block);
            assert_eq!(val, i as u64);
        });
    }

    #[test]
    fn test_is_msb_set() {
        let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
        let sk = ServerKey::new_radix_server_key(&ck);

        for i in 0u8..=255 {
            let enc_i = ck.encrypt_radix(i, 4);
            let is_msb_set = is_msb_set(&sk, &enc_i);
            let dec_is_msb_set = ck.decrypt_bool(&is_msb_set);

            assert_eq!(dec_is_msb_set, i >= 128, "MSB of {} should be {}", i, i >= 128);
        }
    }

    #[test]
    fn test_mix_single_column() {
        // Test vector from AES:
        // Input column: [0xdb, 0x13, 0x53, 0x45]
        // Expected output column: [0x8e, 0x4d, 0xa1, 0xbc]
        let input_column: [u8; 4] = [0xdb, 0x13, 0x53, 0x45];
        let expected_column: [u8; 4] = [0x8e, 0x4d, 0xa1, 0xbc];

        let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
        let sk = ServerKey::new_radix_server_key(&ck);

        let encrypted_column: [RadixCiphertext; 4] =
            input_column.map(|byte| ck.encrypt_radix(byte, 4));

        let mixed_encrypted = mix_single_column(&sk, &encrypted_column);

        let decrypted_column: [u8; 4] =
            mixed_encrypted.map(|ct| ck.decrypt_radix(&ct));

        assert_eq!(
            decrypted_column,
            expected_column,
            "MixColumns on a single column did not produce the expected result"
        );
    }

    #[test]
    fn test_fhe_aes_encrypt() {
        // Official AES-128 test vector:
        // Key:           2b7e1516 28aed2a6 abf71588 09cf4f3c
        // Plaintext:     00112233 44556677 8899aabb ccddeeff
        // Expected CT:   69c4e0d8 6a7b0430 d8cdb780 70b4c55a

        let _key_bytes: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34,
        ];
        let expected_ciphertext: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d,
            0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97,
            0x19, 0x6a, 0x0b, 0x32,
        ];

        // The cleartext round keys for AES-128 as specified in FIPS-197.
        const CLEAR_ROUND_KEYS: [[u8; 16]; 11] = [
            [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
            [0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05],
            [0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f],
            [0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b],
            [0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00],
            [0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc],
            [0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd],
            [0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f],
            [0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f],
            [0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e],
            [0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6],
        ];

        let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
        let sk = ServerKey::new_radix_server_key(&ck);

        let enc_plaintext = encrypt_block(&ck, &plaintext);
        let enc_round_keys: [FheRoundKey; 11] =
            CLEAR_ROUND_KEYS.map(|rk| FheRoundKey(encrypt_block(&ck, &rk)));

        let enc_ciphertext = fhe_aes_encrypt(&sk, enc_plaintext, &enc_round_keys);

        let dec_ciphertext = decrypt_block(&ck, &enc_ciphertext);
        assert_eq!(
            dec_ciphertext,
            expected_ciphertext,
            "FHE AES encryption did not produce the expected ciphertext"
        );
    }
}
