// src/wallet/encryption.rs

use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM
use aes_gcm::aead::{Aead, KeyInit};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::{thread_rng, RngCore};
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// Magic header to identify encrypted wallet files.
const MAGIC: &[u8] = b"COINSWAP";

/// Derives a 256-bit key from a password and salt using PBKDF2-HMAC-SHA256.
pub fn derive_key_from_password(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; 32], Box<dyn Error>> {
    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key_bytes);
    Ok(key_bytes)
}

/// Encrypts wallet data using AES-256-GCM. Returns the full encrypted payload:
/// [ MAGIC | salt(16 bytes) | iv(12 bytes) | ciphertext+tag ].
pub fn encrypt_wallet_data(
    password: &str,
    plaintext: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // 1. Generate a random 16-byte salt.
    let mut salt = [0u8; 16];
    thread_rng().fill_bytes(&mut salt);

    // 2. Derive the encryption key.
    let key_bytes = derive_key_from_password(password, &salt, iterations)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // 3. Generate a random 12-byte IV (nonce).
    let mut iv = [0u8; 12];
    thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    // 4. Encrypt the plaintext.
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // 5. Build the output: [ MAGIC | salt | iv | ciphertext ]
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&iv);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypts wallet data previously encrypted by `encrypt_wallet_data`.
pub fn decrypt_wallet_data(
    password: &str,
    encrypted_data: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Check that the file is at least long enough to contain MAGIC, salt, iv.
    if encrypted_data.len() < MAGIC.len() + 16 + 12 {
        return Err("Encrypted file too short".into());
    }
    // Verify magic header.
    let magic_part = &encrypted_data[..MAGIC.len()];
    if magic_part != MAGIC {
        return Err("Invalid file format: missing magic header".into());
    }
    // Extract salt, iv, and ciphertext.
    let salt_start = MAGIC.len();
    let salt_end = salt_start + 16;
    let iv_start = salt_end;
    let iv_end = iv_start + 12;
    let cipher_start = iv_end;

    let salt = &encrypted_data[salt_start..salt_end];
    let iv = &encrypted_data[iv_start..iv_end];
    let ciphertext = &encrypted_data[cipher_start..];

    // Derive the key.
    let key_bytes = derive_key_from_password(password, salt, iterations)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Decrypt.
    let nonce = Nonce::from_slice(iv);
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed: wrong password or corrupted data")?;
    Ok(plaintext)
}

/// Helper: Encrypt wallet data and write to file.
pub fn encrypt_and_write_to_file(
    password: &str,
    plaintext: &[u8],
    out_path: &Path,
    iterations: u32,
) -> Result<(), Box<dyn Error>> {
    let enc_data = encrypt_wallet_data(password, plaintext, iterations)?;
    let mut file = File::create(out_path)?;
    file.write_all(&enc_data)?;
    Ok(())
}

/// Helper: Read encrypted file from disk and decrypt.
pub fn read_and_decrypt_file(
    password: &str,
    in_path: &Path,
    iterations: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = File::open(in_path)?;
    let mut enc_data = Vec::new();
    file.read_to_end(&mut enc_data)?;
    decrypt_wallet_data(password, &enc_data, iterations)
}
