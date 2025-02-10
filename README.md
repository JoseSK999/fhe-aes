# FHE AES-128

This repo contains the full FHE implementation of the AES-128 _Key Expansion_ algorithm, as well as the _AES Encrypt_ function, using `tfhe-rs`.

The main performance overhead is the AES S-Box byte substitution, performed in both the key derivation and the encryption process for several bytes during multiple rounds. The best solution seems to be using a highly optimized cleartext lookup evaluation, which is provided by the `match_value_parallelized` method from `tfhe-rs` (which takes an encrypted value and a cleartext mapping of 256 values).

For the Key Expansion algorithm we have made the "XOR with Round Constant" non-FHE, as we can apply this bitxor directly to the S-Box (both the Round Constant and the S-Box are in the clear) and use the modified S-Box for the respective byte substitution. Nonetheless, this only saves about 10 homomorphic byte XORs. 

## How to run the binary

You can run the Command Line program with:

```bash
cargo run --release -- --number-of-outputs <NUMBER_OF_OUTPUTS> --iv <IV> --key <KEY>
```

Or, a bit shorter:

```bash
cargo run --release -- -n <NUMBER_OF_OUTPUTS> --iv <IV> --key <KEY>
```

This will run the FHE AES algorithm in counter mode, checking the result of `n` plaintexts, which are incremental values, starting with the `iv` plaintext, and using the provided `key` for the key derivation process.

These `n` AES encryption blocks will run in parallel, but you can disable this via `--no-default-features` (disabling the `parallel_aes` feature). The encryption process is already well parallelized, so running multiple AES encryption functions in parallel may not provide any performance benefit.

Finally, you can also toggle off the Command Line parser and instead use randomly generated keys and IVs, via the `rand_args` feature.

```bash
cargo run --release --features rand_args
```

## How to use the library

The snippet below demonstrates how to use the public API.

```rust
use fhe_aes::{
    encrypt_block,
    decrypt_block,
    key_expansion::fhe_key_expansion,
    cipher::fhe_aes_encrypt,
};
use tfhe::integer::{ClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    // Sample 16-byte key and plaintext.
    let key: [u8; 16] = [0x00; 16];
    let plaintext: [u8; 16] = [0x11; 16];

    // Initialize FHE keys.
    let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    let sk = ServerKey::new_radix_server_key(&ck);

    // Encrypt the AES key and perform key expansion.
    let enc_key = encrypt_block(&ck, &key);
    let fhe_round_keys = fhe_key_expansion(&sk, enc_key);

    // Encrypt the plaintext using FHE AES.
    let enc_plaintext = encrypt_block(&ck, &plaintext);
    let enc_ciphertext = fhe_aes_encrypt(&sk, enc_plaintext, &fhe_round_keys);

    // Decrypt the ciphertext.
    let decrypted = decrypt_block(&ck, &enc_ciphertext);

    println!("AES block output: {:?}", decrypted);
}
```
