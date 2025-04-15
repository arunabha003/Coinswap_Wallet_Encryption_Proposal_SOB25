// Inside wallet/api.rs (pseudo-code)
use coinswap::crypto::aes256gcm;  // hypothetical module for AES-GCM in our project
use coinswap::wallet::encryption; // our new encryption module

impl Wallet {
    pub fn save_to_disk(&self) -> Result<()> {
        // Serialize wallet data to bytes (existing logic)
        let plaintext_bytes = bincode::serialize(&self.inner_data)?;
        if self.encryption_enabled {
            // Encryption enabled – derive key from the user’s password
            let password = self.password.as_ref().expect("Password must be set"); 
            let salt = encryption::generate_salt();
            // Use PBKDF2 to get 256-bit key from password+salt
            let key = encryption::derive_key_pbkdf2(password, &salt);
            // Generate a random 12-byte IV for AES-GCM
            let iv = encryption::random_iv();
            // Encrypt the plaintext wallet bytes (AES-256-GCM)
            let ciphertext = encryption::aes256_gcm_encrypt(&plaintext_bytes, &key, &iv)
                .expect("Encryption failure");
            // Construct the encrypted file format: [MAGIC | salt | iv | ciphertext | tag]
            let encrypted_blob = encryption::format_encrypted_file(&ciphertext, &salt, &iv);
            // Write encrypted blob to the wallet file
            std::fs::write(&self.file_path, &encrypted_blob)?;
        } else {
            // No encryption (legacy mode) – write plaintext
            std::fs::write(&self.file_path, &plaintext_bytes)?;
        }
        Ok(())
    }

    pub fn load_from_disk(path: &Path) -> Result<Wallet> {
        let data = std::fs::read(path)?;
        if encryption::is_encrypted_format(&data) {
            // Encrypted wallet detected by header
            eprint!("Enter wallet password: ");
            let password = read_password_from_tty()?;  // prompt user for password securely
            // Parse salt and IV from file
            let salt = encryption::extract_salt(&data);
            let iv = encryption::extract_iv(&data);
            let ciphertext = encryption::extract_ciphertext(&data);
            // Derive key using provided password and stored salt
            let key = encryption::derive_key_pbkdf2(&password, &salt);
            // Decrypt the ciphertext (AES-256-GCM)
            let plaintext = encryption::aes256_gcm_decrypt(&ciphertext, &key, &iv)
                .map_err(|_| anyhow!("Incorrect password or corrupted wallet"))?;
            // Deserialize plaintext into Wallet structure
            let wallet = bincode::deserialize::<Wallet>(&plaintext)?;
            // Mark that this wallet is using encryption (so future saves encrypt)
            wallet.encryption_enabled = true;
            wallet.password = Some(password);  // store in-memory for reuse until shutdown
            return Ok(wallet);
        } else {
            // Legacy plaintext wallet loading (no password needed)
            let wallet = bincode::deserialize::<Wallet>(&data)?;
            return Ok(wallet);
        }
    }
}
