use fhe_aes::{encrypt_block, decrypt_block, key_expansion::fhe_key_expansion, cipher::fhe_aes_encrypt};

use clap::Parser;
use std::time::Instant;
use aes::Aes128;
use aes::cipher::{KeyInit, BlockEncrypt, generic_array::GenericArray};
use std::convert::TryInto;
#[cfg(feature = "rand_args")]
use rand::Rng;
#[cfg(feature = "parallel_aes")]
use rayon::prelude::*;
use tfhe::integer::{ClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Number of outputs to generate.
    #[arg(short = 'n', long)]
    number_of_outputs: usize,

    /// Initialization vector (IV) as a 32-character hex string (16 bytes).
    #[arg(long)]
    iv: String,

    /// AES-128 key as a 32-character hex string (16 bytes).
    #[arg(long)]
    key: String,
}

#[cfg(feature = "parallel_aes")]
macro_rules! iter_range {
    ($range:expr) => {
        $range.into_par_iter()
    };
}
#[cfg(not(feature = "parallel_aes"))]
macro_rules! iter_range {
    ($range:expr) => {
        $range.into_iter()
    };
}

fn main() {
    let (n, key_bytes, iv_bytes) = parse_args();

    let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    let sk = ServerKey::new_radix_server_key(&ck);
    let enc_key = encrypt_block(&ck, &key_bytes);

    // ----------------------------
    // AES-128 Key Expansion
    // ----------------------------
    let start_key = Instant::now();
    let fhe_round_keys = fhe_key_expansion(&sk, enc_key);
    let key_expansion_elapsed = start_key.elapsed();
    println!("AES key expansion took: {key_expansion_elapsed:?}");

    let cipher = Aes128::new(GenericArray::from_slice(&key_bytes));

    // ----------------------------
    // Cleartext AES-128 Encryption/Decryption (Counter Mode)
    // ----------------------------
    let iv_u128 = u128::from_be_bytes(iv_bytes);
    let mut clear_ciphertexts = Vec::with_capacity(n);

    // For each block, compute cleartext encryption.
    for i in 0..n {
        let plaintext = iv_u128.wrapping_add(i as u128).to_be_bytes();
        let mut block = GenericArray::clone_from_slice(&plaintext);
        cipher.encrypt_block(&mut block);
        clear_ciphertexts.push(block);
    }

    // ----------------------------
    // FHE AES-128 Encryption/Decryption (Counter Mode)
    // ----------------------------
    let start_aes = Instant::now();
    let fhe_ciphertexts: Vec<_> = iter_range!(0..n)
        .map(|i| {
            let plaintext = iv_u128.wrapping_add(i as u128).to_be_bytes();
            let fhe_plaintext = encrypt_block(&ck, &plaintext);
            fhe_aes_encrypt(&sk, fhe_plaintext, &fhe_round_keys)
        })
        .collect();
    let elapsed = start_aes.elapsed();

    // Compare each FHE ciphertext (after decryption) with the cleartext AES ciphertext.
    for (i, (clear_ct, fhe_ct)) in clear_ciphertexts.iter().zip(fhe_ciphertexts.iter()).enumerate() {
        // Decrypt the FHE ciphertext block.
        let decrypted_fhe: [u8; 16] = decrypt_block(&ck, &fhe_ct);
        assert_eq!(
            clear_ct.as_slice(),
            &decrypted_fhe,
            "Mismatch in encryption for block {}",
            i
        );
    }
    println!("AES of #{n} outputs computed in: {elapsed:?}");
}

#[cfg(not(feature = "rand_args"))]
fn parse_args() -> (usize, [u8; 16], [u8; 16]) {
    let args = Args::parse();
    let n = args.number_of_outputs;

    // Convert hex strings into 16-byte arrays using the `hex` crate.
    let key_bytes: [u8; 16] = hex::decode(&args.key)
        .expect("Invalid hex for key")
        .try_into()
        .expect("Key must be 16 bytes");
    let iv_bytes: [u8; 16] = hex::decode(&args.iv)
        .expect("Invalid hex for iv")
        .try_into()
        .expect("IV must be 16 bytes");

    (n, key_bytes, iv_bytes)
}

#[cfg(feature = "rand_args")]
fn parse_args() -> (usize, [u8; 16], [u8; 16]) {
    // Testing iv and iv + 1 should be enough
    let n = 2;

    let mut rng = rand::rng();
    let mut key_bytes = [0u8; 16];
    let mut iv_bytes = [0u8; 16];

    rng.fill(&mut key_bytes);
    rng.fill(&mut iv_bytes);

    (n, key_bytes, iv_bytes)
}
