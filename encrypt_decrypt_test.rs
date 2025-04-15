#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "testpassword";
        let data = b"Dummy wallet data";
        // Encrypt the data
        let salt = generate_salt();
        let key = derive_key_pbkdf2(password, &salt);
        let iv = random_iv();
        let ciphertext = aes256_gcm_encrypt(data, &key, &iv).expect("encryption should succeed");
        // Decrypt the data
        let decrypted = aes256_gcm_decrypt(&ciphertext, &key, &iv).expect("decryption should succeed");
        assert_eq!(decrypted, data, "Decrypted data should match original");
    }

    #[test]
    fn test_decrypt_bad_password() {
        let password = "correcthorsebatterystaple";
        let wrong_password = "Tr0ub4dor&3";  // an incorrect password
        let data = b"Secret keys";
        let salt = generate_salt();
        let key = derive_key_pbkdf2(password, &salt);
        let iv = [0u8; 12];
        let ciphertext = aes256_gcm_encrypt(data, &key, &iv).unwrap();
        // Try decrypting with a wrong key derived from wrong password
        let wrong_key = derive_key_pbkdf2(wrong_password, &salt);
        let result = aes256_gcm_decrypt(&ciphertext, &wrong_key, &iv);
        assert!(result.is_err(), "Decryption should fail with wrong password");
    }

    #[test]
    fn test_encrypted_file_format() {
        let password = "mypassword";
        // Save a wallet and then read the file to verify format
        let wallet = Wallet::new_empty(); 
        wallet.set_password(password);
        wallet.save_to_disk().expect("save should succeed");
        let bytes = std::fs::read(&wallet.file_path).unwrap();
        assert!(is_encrypted_format(&bytes), "Wallet file should have encrypted format header");
        // The file should contain salt and iv of expected lengths at known positions
        let salt = extract_salt(&bytes);
        let iv = extract_iv(&bytes);
        assert_eq!(salt.len(), 16);
        assert_eq!(iv.len(), 12);
    }
}
