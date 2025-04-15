// Inside makerd RPC/command handling loop (pseudo-code)
match command.name.as_str() {
    "backup" => {
        // Lock wallet and flush to disk to ensure we have the latest state
        self.wallet.lock(); 
        self.wallet.save_to_disk()?;
        self.wallet.unlock();
        // Perform local backup (copy file)
        let wallet_path = self.wallet.file_path.clone();
        let backup_path = backup_local_file(&wallet_path)?;
        // Optionally upload to cloud
        if self.config.enable_cloud_backup {
            if let Err(e) = upload_backup_to_s3(&backup_path) {
                log::error!("Cloud upload failed: {}", e);
            }
        }
        return Ok("Backup completed");
    }
    "restore" => {
        // The command is expected to include the backup file path and password
        let backup_path = command.params.get("file").expect("No file param");
        let password = command.params.get("password").expect("No password param");
        // Attempt to load and decrypt the backup file
        match Wallet::load_from_disk(Path::new(backup_path)) {
            Ok(new_wallet) => {
                // We successfully decrypted with the given password
                self.wallet = new_wallet;  // replace current in-memory wallet
                self.wallet.save_to_disk()?;  // save (encrypted with same password) as current wallet file
                return Ok("Restore successful");
            }
            Err(e) => {
                log::error!("Restore failed: {}", e);
                return Err(anyhow!("Restore failed: {}", e));
            }
        }
    }
    // ... other RPC commands ...
}
