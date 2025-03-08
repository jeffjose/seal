use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::Result;
use argon2::Argon2;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};
use walkdir::WalkDir;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const EXTENSION: &str = "sealed";
const METADATA_FILE: &str = "metadata.sealed";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt files in the current directory
    Encrypt,
    /// Decrypt previously encrypted files
    Decrypt,
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    salt: String,
    files: HashMap<String, String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt => encrypt_directory()?,
        Commands::Decrypt => decrypt_directory()?,
    }

    Ok(())
}

fn get_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    Ok(read_password()?)
}

fn derive_key(password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    let mut key = vec![0u8; 32];
    Argon2::default()
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Failed to derive key: {}", e))?;
    Ok(key)
}

fn encrypt_file(path: &Path, cipher: &Aes256Gcm) -> Result<Vec<u8>> {
    let mut nonce = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let contents = fs::read(path)?;
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), contents.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    Ok([nonce.as_slice(), &encrypted].concat())
}

fn decrypt_file(path: &Path, cipher: &Aes256Gcm) -> Result<Vec<u8>> {
    let contents = fs::read(path)?;
    let (nonce, ciphertext) = contents.split_at(NONCE_LEN);

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

fn encrypt_directory() -> Result<()> {
    encrypt_directory_with_password(&get_password("Enter password for encryption: ")?)
}

fn encrypt_directory_with_password(password: &str) -> Result<()> {
    let mut salt = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let mut metadata = Metadata {
        salt: URL_SAFE_NO_PAD.encode(&salt),
        files: HashMap::new(),
    };

    // Encrypt each file
    for entry in WalkDir::new(".")
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| {
            !e.file_name()
                .to_str()
                .map(|s| s.ends_with(EXTENSION))
                .unwrap_or(false)
        })
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let encrypted = encrypt_file(path, &cipher)?;

        // Generate encrypted filename
        let original_name = path.to_string_lossy().into_owned();
        let encrypted_name = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(path.to_string_lossy().as_bytes()),
            EXTENSION
        );

        metadata
            .files
            .insert(encrypted_name.clone(), original_name.clone());

        // Write encrypted file
        fs::write(&encrypted_name, encrypted)?;
        fs::remove_file(path)?;

        println!("Encrypted: {}", original_name);
    }

    // Save metadata with salt first
    fs::write(
        METADATA_FILE,
        format!(
            "{}\n{}",
            metadata.salt,
            serde_json::to_string(&metadata.files)?
        ),
    )?;

    println!("Encryption complete!");
    Ok(())
}

fn decrypt_directory() -> Result<()> {
    decrypt_directory_with_password(&get_password("Enter password for decryption: ")?)
}

fn decrypt_directory_with_password(password: &str) -> Result<()> {
    // Read metadata file
    let metadata_contents = fs::read_to_string(METADATA_FILE)?;
    let mut lines = metadata_contents.lines();

    // First line is the salt
    let salt = URL_SAFE_NO_PAD.decode(
        lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid metadata file"))?,
    )?;

    // Rest is the JSON data
    let files: HashMap<String, String> =
        serde_json::from_str(&lines.collect::<Vec<_>>().join("\n"))?;

    let key = derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    // Decrypt each file
    for (encrypted_name, original_name) in files {
        let decrypted = decrypt_file(Path::new(&encrypted_name), &cipher)?;
        fs::write(&original_name, decrypted)?;
        fs::remove_file(&encrypted_name)?;
        println!("Decrypted: {}", original_name);
    }

    fs::remove_file(METADATA_FILE)?;
    println!("Decryption complete!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    fn setup_test_directory() -> Result<TempDir> {
        let temp_dir = TempDir::new()?;
        std::env::set_current_dir(&temp_dir)?;

        // Create some test files
        let test_files = vec![
            ("test1.txt", "Hello World"),
            ("test2.txt", "Some other content"),
            ("nested/test3.txt", "Nested file content"),
        ];

        for (path, content) in test_files {
            if let Some(parent) = Path::new(path).parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = File::create(path)?;
            file.write_all(content.as_bytes())?;
        }

        Ok(temp_dir)
    }

    #[test]
    fn test_key_derivation() -> Result<()> {
        let password = b"test_password";
        let salt = vec![0u8; SALT_LEN];
        let key = derive_key(password, &salt)?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    #[test]
    fn test_file_encryption_decryption() -> Result<()> {
        let password = b"test_password";
        let salt = vec![0u8; SALT_LEN];
        let key = derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        let temp_dir = TempDir::new()?;
        let test_file = temp_dir.path().join("test.txt");
        let content = b"Hello, World!";
        fs::write(&test_file, content)?;

        let encrypted = encrypt_file(&test_file, &cipher)?;
        assert_ne!(encrypted, content);

        let decrypted = cipher
            .decrypt(
                Nonce::from_slice(&encrypted[..NONCE_LEN]),
                &encrypted[NONCE_LEN..],
            )
            .unwrap();
        assert_eq!(decrypted, content);

        Ok(())
    }

    #[test]
    fn test_full_directory_encryption_decryption() -> Result<()> {
        let _temp_dir = setup_test_directory()?;
        let test_password = "test_password";

        // Store original file contents
        let mut original_contents = HashMap::new();
        for entry in WalkDir::new(".").min_depth(1) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let path = entry.path().to_string_lossy().into_owned();
                let content = fs::read_to_string(entry.path())?;
                original_contents.insert(path, content);
            }
        }

        // Run encryption
        encrypt_directory_with_password(test_password)?;

        // Verify files are encrypted
        for path in original_contents.keys() {
            assert!(!Path::new(path).exists(), "Original file should be deleted");
            assert!(
                fs::read_dir(".").unwrap().any(|e| e
                    .unwrap()
                    .path()
                    .to_string_lossy()
                    .ends_with(EXTENSION)),
                "Encrypted files should exist"
            );
        }

        // Run decryption
        decrypt_directory_with_password(test_password)?;

        // Verify decrypted contents match original
        for (path, original_content) in original_contents {
            let decrypted_content = fs::read_to_string(path)?;
            assert_eq!(decrypted_content, original_content);
        }

        Ok(())
    }
}
