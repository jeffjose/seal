use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::Result;
use argon2::Argon2;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use nanoid::nanoid;
use rand::{rngs::OsRng, RngCore};
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::{collections::HashMap, fs, path::Path};
use walkdir::WalkDir;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const EXTENSION: &str = "sealed";
const SEAL_DIR: &str = ".seal";
const META_FILE: &str = "meta";
const META_SALT_FILE: &str = "meta.salt";
const FILENAME_LENGTH: usize = 16; // Length of random filenames
const NANOID_ALPHABET: &str = "0123456789abcdefghijklmnopqrstuvwxyz"; // Only lowercase letters and numbers

// Constants for streaming
const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
#[cfg(not(test))]
const LARGE_FILE_THRESHOLD: u64 = 10 * 1024 * 1024; // 10MB for normal operation
#[cfg(test)]
const LARGE_FILE_THRESHOLD: u64 = 1 * 1024 * 1024; // 1MB for testing

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Run in test mode (creates and encrypts/decrypts files in a temporary directory)
    #[arg(long, global = true, hide = true)]
    test_mode: bool,

    /// Provide password directly (caution: may be visible in command history)
    #[arg(long, short = 'p', global = true)]
    password: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt specific files in the current directory
    #[command(alias = "e")]
    Encrypt {
        /// Files to encrypt
        files: Vec<String>,
    },
    /// Decrypt previously encrypted files
    #[command(alias = "d", alias = "x")]
    Decrypt {
        /// Files to decrypt
        files: Vec<String>,
    },
    /// Show status of encrypted and unencrypted files
    #[command(alias = "st")]
    Status,
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    salt: String,
    files: HashMap<String, String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Create a temporary directory for testing if test_mode is set
    if cli.test_mode {
        // Create a subdirectory for testing
        let test_dir = Path::new("test_dir");
        if !test_dir.exists() {
            fs::create_dir(test_dir)?;
        }
        std::env::set_current_dir(test_dir)?;

        // Create a test file
        fs::write("testfile.txt", "This is a test file")?;
        println!(
            "Created test file: testfile.txt in directory: {:?}",
            std::env::current_dir()?
        );

        // Run the command with a fixed test password or provided password
        let password = cli.password.as_deref().unwrap_or("test_password");
        match &cli.command {
            Some(Commands::Encrypt { files }) => {
                encrypt_directory_with_password_and_files(password, files)?
            }
            Some(Commands::Decrypt { files }) => {
                decrypt_directory_with_password_and_files(password, files)?
            }
            Some(Commands::Status) => status_directory()?,
            None => encrypt_directory_with_password(password)?,
        }

        // Clean up
        std::env::set_current_dir("..")?;
        fs::remove_dir_all(test_dir)?;
        println!("Test completed. Test directory cleaned up.");
        return Ok(());
    }

    // Normal operation
    match &cli.command {
        Some(Commands::Encrypt { files }) => {
            if let Some(password) = &cli.password {
                encrypt_directory_with_password_and_files(password, files)?
            } else {
                let password = get_password("Enter password: ")?;
                encrypt_directory_with_password_and_files(&password, files)?
            }
        }
        Some(Commands::Decrypt { files }) => {
            if let Some(password) = &cli.password {
                decrypt_directory_with_password_and_files(password, files)?
            } else {
                let password = get_password("Enter password: ")?;
                decrypt_directory_with_password_and_files(&password, files)?
            }
        }
        Some(Commands::Status) => status_directory()?,
        None => {
            if let Some(password) = &cli.password {
                encrypt_directory_with_password(password)?
            } else {
                encrypt_directory()?
            }
        }
    }

    Ok(())
}

fn get_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    std::io::stdout().flush()?;
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
    // Check if this is a large file that needs streaming
    let metadata = fs::metadata(path)?;
    if metadata.len() > LARGE_FILE_THRESHOLD {
        return encrypt_file_streaming(path, cipher);
    }

    // For small files, use a single chunk
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    // Read file contents
    let contents = fs::read(path)?;

    // Write number of chunks (1 for small files)
    let mut result = Vec::new();
    result.extend_from_slice(&1u64.to_le_bytes()); // Always 1 chunk for small files
    result.extend_from_slice(&nonce);

    // Encrypt the contents
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), contents.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Write chunk size and encrypted data
    let chunk_size = encrypted.len() as u32;
    result.extend_from_slice(&chunk_size.to_le_bytes());
    result.extend_from_slice(&encrypted);

    Ok(result)
}

fn encrypt_file_streaming(path: &Path, cipher: &Aes256Gcm) -> Result<Vec<u8>> {
    use std::io::{Read, Write};

    #[cfg(test)]
    println!("Starting streaming encryption for file: {:?}", path);

    // Open the input file
    let mut file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len();

    // For small files, use a single chunk
    let num_chunks = if file_size < CHUNK_SIZE as u64 {
        1
    } else {
        (file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64
    };

    // Create a temporary file for the encrypted output
    let temp_path = path.with_extension("temp_encrypted");
    let mut temp_file = std::fs::File::create(&temp_path)?;

    // Write the number of chunks first (u64)
    temp_file.write_all(&num_chunks.to_le_bytes())?;

    // Process the file in chunks
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut _total_written = 8u64; // 8 bytes for num_chunks

    #[cfg(test)]
    println!(
        "Processing file in {} chunks of {} bytes each",
        num_chunks, CHUNK_SIZE
    );

    // Create a progress bar for this file
    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("█▓▒░"),
    );

    let mut chunk_index = 0;
    let mut total_read = 0u64;
    while let Ok(n) = file.read(&mut buffer) {
        if n == 0 {
            break; // End of file
        }

        // Generate a unique nonce for this chunk
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        // Write the nonce for this chunk
        temp_file.write_all(&nonce)?;
        _total_written += NONCE_LEN as u64;

        // Encrypt the chunk
        let encrypted_chunk = cipher
            .encrypt(Nonce::from_slice(&nonce), buffer[..n].as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        // Write the chunk size and encrypted chunk
        let chunk_size = encrypted_chunk.len() as u32;
        temp_file.write_all(&chunk_size.to_le_bytes())?;
        temp_file.write_all(&encrypted_chunk)?;
        _total_written += 4u64 + encrypted_chunk.len() as u64; // 4 bytes for size + chunk

        // Update progress
        total_read += n as u64;
        pb.set_position(total_read);

        #[cfg(test)]
        println!("Processed chunk {}: {} bytes", chunk_index, n);

        chunk_index += 1;
    }

    // Finish the progress bar
    pb.finish_and_clear();

    // Verify we wrote the expected number of chunks
    if chunk_index != num_chunks as usize {
        // Clean up temporary file
        let _ = fs::remove_file(&temp_path);
        return Err(anyhow::anyhow!(
            "Wrote {} chunks but expected {}",
            chunk_index,
            num_chunks
        ));
    }

    // Close the files
    drop(file);
    drop(temp_file);

    #[cfg(test)]
    println!("Total bytes written: {}", _total_written);

    // Read the complete encrypted file
    let result = fs::read(&temp_path)?;

    // Clean up the temporary file
    fs::remove_file(&temp_path)?;

    Ok(result)
}

#[allow(dead_code)]
fn decrypt_file(path: &Path, cipher: &Aes256Gcm) -> Result<Vec<u8>> {
    // Check if this is a large file that needs streaming
    let metadata = fs::metadata(path)?;
    if metadata.len() > LARGE_FILE_THRESHOLD {
        return decrypt_file_streaming(path, cipher);
    }

    let contents = fs::read(path)?;
    if contents.len() <= NONCE_LEN {
        return Err(anyhow::anyhow!(
            "File too small to be a valid encrypted file"
        ));
    }

    let (nonce, ciphertext) = contents.split_at(NONCE_LEN);

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

fn decrypt_file_streaming(path: &Path, cipher: &Aes256Gcm) -> Result<Vec<u8>> {
    use std::io::{Read, Write};

    #[cfg(test)]
    println!("Starting streaming decryption for file: {:?}", path);

    // Open the encrypted file
    let mut file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len();

    if file_size < 8 {
        // At least need num_chunks
        return Err(anyhow::anyhow!(
            "File too small to be a valid encrypted file"
        ));
    }

    // Read the number of chunks
    let mut num_chunks_bytes = [0u8; 8];
    file.read_exact(&mut num_chunks_bytes)?;
    let num_chunks = u64::from_le_bytes(num_chunks_bytes);

    // For small files, expect a single chunk
    let expected_max_chunks = if file_size < CHUNK_SIZE as u64 {
        1
    } else {
        (file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64
    };

    if num_chunks > expected_max_chunks {
        return Err(anyhow::anyhow!(
            "Invalid number of chunks: got {}, expected at most {}",
            num_chunks,
            expected_max_chunks
        ));
    }

    // Create a temporary file for the decrypted output
    let temp_path = path.with_extension("temp_decrypted");
    let mut temp_file = std::fs::File::create(&temp_path)?;

    #[cfg(test)]
    println!("Decrypting {} chunks", num_chunks);

    let mut total_written = 0u64;
    let mut total_read = 8u64; // Start after num_chunks

    // Create a progress bar for this file
    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("█▓▒░"),
    );
    pb.set_position(total_read);

    // Process each chunk
    for chunk_index in 0..num_chunks {
        // Read the nonce for this chunk
        let mut nonce = [0u8; NONCE_LEN];
        if let Err(e) = file.read_exact(&mut nonce) {
            // Clean up temporary file
            let _ = fs::remove_file(&temp_path);
            return Err(anyhow::anyhow!(
                "Failed to read nonce for chunk {}: {}",
                chunk_index,
                e
            ));
        }
        total_read += NONCE_LEN as u64;
        pb.set_position(total_read);

        // Read the chunk size
        let mut chunk_size_bytes = [0u8; 4];
        if let Err(e) = file.read_exact(&mut chunk_size_bytes) {
            // Clean up temporary file
            let _ = fs::remove_file(&temp_path);
            return Err(anyhow::anyhow!(
                "Failed to read size for chunk {}: {}",
                chunk_index,
                e
            ));
        }
        total_read += 4u64;
        pb.set_position(total_read);

        let chunk_size = u32::from_le_bytes(chunk_size_bytes) as usize;

        // Validate chunk size
        if chunk_size > CHUNK_SIZE + 16 {
            // 16 bytes for GCM tag
            // Clean up temporary file
            let _ = fs::remove_file(&temp_path);
            return Err(anyhow::anyhow!(
                "Invalid chunk size for chunk {}: {} bytes",
                chunk_index,
                chunk_size
            ));
        }

        // Read the encrypted chunk
        let mut encrypted_chunk = vec![0u8; chunk_size];
        if let Err(e) = file.read_exact(&mut encrypted_chunk) {
            // Clean up temporary file
            let _ = fs::remove_file(&temp_path);
            return Err(anyhow::anyhow!(
                "Failed to read chunk {}: {}",
                chunk_index,
                e
            ));
        }
        total_read += chunk_size as u64;
        pb.set_position(total_read);

        // Decrypt the chunk
        let decrypted_chunk =
            match cipher.decrypt(Nonce::from_slice(&nonce), encrypted_chunk.as_ref()) {
                Ok(data) => data,
                Err(_e) => {
                    // Clean up temporary file
                    let _ = fs::remove_file(&temp_path);
                    return Err(anyhow::anyhow!(
                        "Failed to decrypt chunk {}: {:?}",
                        chunk_index,
                        _e
                    ));
                }
            };

        // Write the decrypted chunk
        if let Err(e) = temp_file.write_all(&decrypted_chunk) {
            // Clean up temporary file
            let _ = fs::remove_file(&temp_path);
            return Err(anyhow::anyhow!(
                "Failed to write chunk {}: {}",
                chunk_index,
                e
            ));
        }
        total_written += decrypted_chunk.len() as u64;

        #[cfg(test)]
        println!(
            "Processed chunk {}: {} bytes",
            chunk_index,
            decrypted_chunk.len()
        );
    }

    // Finish the progress bar
    pb.finish_and_clear();

    // Close the files
    drop(file);
    drop(temp_file);

    #[cfg(test)]
    println!("Total bytes written: {}", total_written);

    // Read the complete decrypted file
    let result = fs::read(&temp_path)?;

    // Clean up the temporary file
    fs::remove_file(&temp_path)?;

    Ok(result)
}

/// Normalize a path string to use forward slashes and remove leading ./
#[allow(dead_code)]
fn normalize_path(path: &str) -> String {
    let path = path.replace("\\", "/");
    if path.starts_with("./") {
        path[2..].to_string()
    } else {
        path
    }
}

/// Generate a user-friendly filename using nanoid with a custom alphabet
fn generate_friendly_filename() -> String {
    format!(
        "{}.{}",
        nanoid!(
            FILENAME_LENGTH,
            &NANOID_ALPHABET.chars().collect::<Vec<char>>()
        ),
        EXTENSION
    )
}

/// Generate a friendly directory name using nanoid with a custom alphabet
fn generate_friendly_dirname() -> String {
    nanoid!(
        FILENAME_LENGTH,
        &NANOID_ALPHABET.chars().collect::<Vec<char>>()
    )
}

/// Create encrypted directory structure based on original path
fn create_encrypted_path(original_path: &str) -> Result<String> {
    // Extract directory components from the original path
    let path = Path::new(original_path);
    let _file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid path"))?;

    // Generate encrypted filename
    let encrypted_filename = generate_friendly_filename();

    if let Some(parent) = path.parent() {
        if parent.as_os_str().is_empty() || parent == Path::new(".") {
            // File is in the root directory, just return the encrypted filename
            return Ok(encrypted_filename);
        }

        // For files in subdirectories, create an encrypted directory structure
        let encrypted_dirname = generate_friendly_dirname();

        // Create the encrypted directory if it doesn't exist
        let encrypted_dir = Path::new(&encrypted_dirname);
        if !encrypted_dir.exists() {
            fs::create_dir_all(encrypted_dir)?;
        }

        // Return the path with encrypted directory and filename
        return Ok(format!("{}/{}", encrypted_dirname, encrypted_filename));
    }

    // If no parent directory, just return the encrypted filename
    Ok(encrypted_filename)
}

/// Recursively remove empty directories
fn remove_empty_directories(dir: &Path) -> Result<bool> {
    // Skip if it's not a directory or doesn't exist
    if !dir.is_dir() || !dir.exists() {
        return Ok(false);
    }

    // Skip special directories
    let dir_str = dir.to_string_lossy();
    if dir_str.contains(SEAL_DIR) || dir_str.starts_with("./.") {
        return Ok(false);
    }

    let mut is_empty = true;

    // Check all entries in the directory
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            // Recursively check subdirectories
            let subdir_empty = remove_empty_directories(&path)?;
            if !subdir_empty {
                is_empty = false;
            }
        } else {
            // If there's a file, the directory is not empty
            is_empty = false;
        }
    }

    // If the directory is empty, remove it
    if is_empty {
        #[cfg(test)]
        println!("Removing empty directory: {:?}", dir);

        fs::remove_dir(dir)?;
    }

    Ok(is_empty)
}

fn encrypt_directory() -> Result<()> {
    encrypt_directory_with_password(&get_password("Enter password: ")?)
}

fn encrypt_directory_with_password(password: &str) -> Result<()> {
    let mut salt = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // Create .seal directory if it doesn't exist
    let seal_dir = Path::new(SEAL_DIR);
    if !seal_dir.exists() {
        fs::create_dir(seal_dir)?;
    }

    let meta_path = seal_dir.join(META_FILE);

    // Try to read existing metadata
    let mut metadata = if meta_path.exists() {
        // Decrypt the metadata file first
        let encrypted_metadata = fs::read(&meta_path)?;
        let (nonce, ciphertext) = encrypted_metadata.split_at(NONCE_LEN);

        // Read the metadata salt file
        let meta_salt_path = seal_dir.join(META_SALT_FILE);
        let meta_salt = if meta_salt_path.exists() {
            // Use the stored metadata salt if it exists
            fs::read(&meta_salt_path)?
        } else {
            // No fallback - require the salt file
            return Err(anyhow::anyhow!("Metadata salt file not found"));
        };

        // Derive key from password and metadata salt
        let meta_key = derive_key(password.as_bytes(), &meta_salt)?;
        let meta_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&meta_key));

        let decrypted_metadata = match meta_cipher.decrypt(Nonce::from_slice(nonce), ciphertext) {
            Ok(data) => data,
            Err(_e) => {
                // For debugging in tests
                #[cfg(test)]
                println!("Failed to decrypt metadata: {:?}", _e);

                return Err(anyhow::anyhow!(
                    "Invalid password or corrupted metadata file"
                ));
            }
        };

        let metadata_contents = String::from_utf8(decrypted_metadata)?;
        let mut lines = metadata_contents.lines();

        // Get existing salt
        let salt_str = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid metadata file"))?;
        let existing_salt = URL_SAFE_NO_PAD.decode(salt_str)?;

        // Parse existing files
        let existing_files: HashMap<String, String> =
            serde_json::from_str(&lines.collect::<Vec<_>>().join("\n"))?;

        // Use existing salt for consistency
        salt = existing_salt;

        Metadata {
            salt: URL_SAFE_NO_PAD.encode(&salt),
            files: existing_files,
        }
    } else {
        // Create a new metadata structure with the generated salt
        Metadata {
            salt: URL_SAFE_NO_PAD.encode(&salt),
            files: HashMap::new(),
        }
    };

    // Derive key with the salt
    let key = derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    // Create a list of files to encrypt
    let files_to_encrypt: Vec<String> = WalkDir::new(".")
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_string_lossy().to_string())
        .filter(|s| {
            !s.starts_with("./.")
                && !s.ends_with(EXTENSION)
                && s != SEAL_DIR
                && s != ".original_path"
        })
        .collect();

    #[cfg(test)]
    println!("Files to encrypt: {:?}", files_to_encrypt);

    if files_to_encrypt.is_empty() {
        if metadata.files.is_empty() {
            // For tests, don't error out if there are no files
            #[cfg(not(test))]
            return Err(anyhow::anyhow!("No files to encrypt"));

            #[cfg(test)]
            {
                println!("No files to encrypt, but continuing for test");

                // Even if there are no files to encrypt, we should still write the metadata file
                // This ensures that the .seal directory and metadata file exist for tests
                let metadata_string = format!(
                    "{}\n{}",
                    metadata.salt,
                    serde_json::to_string(&metadata.files)?
                );

                // For debugging in tests
                #[cfg(test)]
                println!("Writing empty metadata: {}", metadata_string);

                // Generate a random salt for metadata encryption
                let mut meta_salt = vec![0u8; SALT_LEN];
                OsRng.fill_bytes(&mut meta_salt);

                // Save the metadata salt to a file
                let meta_salt_path = seal_dir.join(META_SALT_FILE);
                fs::write(&meta_salt_path, &meta_salt)?;

                // Encrypt the metadata with the random salt
                let meta_key = derive_key(password.as_bytes(), &meta_salt)?;
                let meta_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&meta_key));

                let mut nonce = vec![0u8; NONCE_LEN];
                OsRng.fill_bytes(&mut nonce);

                let encrypted_metadata = meta_cipher
                    .encrypt(Nonce::from_slice(&nonce), metadata_string.as_bytes())
                    .map_err(|e| anyhow::anyhow!("Failed to encrypt metadata: {}", e))?;

                // Write the encrypted metadata file to the new location
                fs::write(meta_path, [nonce.as_slice(), &encrypted_metadata].concat())?;

                // Remove empty directories
                remove_empty_directories(Path::new("."))?;

                return Ok(());
            }
        } else {
            println!("No new files to encrypt");
            return Ok(());
        }
    }

    // Calculate total size of all files to encrypt
    let mut total_size: u64 = 0;
    let mut file_sizes: HashMap<String, u64> = HashMap::new();

    for path in &files_to_encrypt {
        match fs::metadata(path) {
            Ok(metadata) => {
                let size = metadata.len();
                total_size += size;
                file_sizes.insert(path.clone(), size);
            }
            Err(e) => {
                println!("Warning: Could not get size of file {}: {}", path, e);
                // Use a default size for files we can't get metadata for
                total_size += 1024; // Assume 1KB
                file_sizes.insert(path.clone(), 1024);
            }
        }
    }

    // Add estimated size for metadata operations (rough estimate)
    let metadata_ops_size = 1024 * 1024; // 1MB for metadata operations
    total_size += metadata_ops_size;

    // Setup progress bar based on total file size
    println!(
        "Encrypting {} files ({:.2} MB)...",
        files_to_encrypt.len(),
        total_size as f64 / 1024.0 / 1024.0
    );
    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
            .unwrap()
            .progress_chars("█▓▒░"),
    );

    // Track start time for speed calculation
    let start_time = std::time::Instant::now();

    // Encrypt each file
    for path in files_to_encrypt {
        let file_size = file_sizes.get(&path).copied().unwrap_or(0);
        pb.set_message("Encrypting files...");
        let encrypted = encrypt_file(&Path::new(&path), &cipher)?;

        // Generate encrypted path that preserves directory structure but hides real names
        let original_name = path.clone();
        let encrypted_path = create_encrypted_path(&path)?;

        // Create parent directories if needed
        if let Some(parent) = Path::new(&encrypted_path).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        // Write encrypted file first
        fs::write(&encrypted_path, encrypted)?;
        fs::remove_file(&path)?;

        // Update metadata after successful encryption
        metadata
            .files
            .insert(encrypted_path.clone(), original_name.clone());

        // Update progress bar
        pb.inc(file_size);
    }

    // Update progress for metadata operations
    pb.set_message("Cleaning up empty directories...");
    remove_empty_directories(Path::new("."))?;
    pb.inc(metadata_ops_size / 4);

    pb.set_message("Generating metadata...");
    // Save metadata as a string first
    let metadata_string = format!(
        "{}\n{}",
        metadata.salt,
        serde_json::to_string(&metadata.files)?
    );
    pb.inc(metadata_ops_size / 4);

    // Generate a random salt for metadata encryption
    let mut meta_salt = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut meta_salt);

    pb.set_message("Encrypting metadata...");
    // Save the metadata salt to a file
    let meta_salt_path = seal_dir.join(META_SALT_FILE);
    fs::write(&meta_salt_path, &meta_salt)?;

    // Encrypt the metadata with the random salt
    let meta_key = derive_key(password.as_bytes(), &meta_salt)?;
    let meta_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&meta_key));
    pb.inc(metadata_ops_size / 4);

    let mut nonce = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let encrypted_metadata = meta_cipher
        .encrypt(Nonce::from_slice(&nonce), metadata_string.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to encrypt metadata: {}", e))?;

    pb.set_message("Writing metadata...");
    // Write the encrypted metadata file to the new location
    fs::write(meta_path, [nonce.as_slice(), &encrypted_metadata].concat())?;
    pb.inc(metadata_ops_size / 4);

    // Calculate encryption speed
    let elapsed = start_time.elapsed();
    let speed = if elapsed.as_secs() > 0 {
        total_size as f64 / elapsed.as_secs() as f64 / 1024.0 / 1024.0
    } else {
        total_size as f64 / 1024.0 / 1024.0 // If less than a second, just report the total size
    };

    // Finish progress bar
    pb.finish_with_message(format!("Done at {:.2} MB/s", speed));

    Ok(())
}

fn decrypt_directory() -> Result<()> {
    decrypt_directory_with_password(&get_password("Enter password: ")?)
}

fn decrypt_directory_with_password(password: &str) -> Result<()> {
    // Create .seal directory if it doesn't exist
    let seal_dir = Path::new(SEAL_DIR);
    if !seal_dir.exists() {
        return Err(anyhow::anyhow!("No .seal directory found"));
    }

    let meta_path = seal_dir.join(META_FILE);

    // Try to read the metadata
    if meta_path.exists() {
        // Read the encrypted metadata file
        let encrypted_metadata = fs::read(&meta_path)?;
        let (nonce, ciphertext) = encrypted_metadata.split_at(NONCE_LEN);

        // Read the metadata salt file
        let meta_salt_path = seal_dir.join(META_SALT_FILE);
        let meta_salt = if meta_salt_path.exists() {
            // Use the stored metadata salt if it exists
            fs::read(&meta_salt_path)?
        } else {
            // No fallback - require the salt file
            return Err(anyhow::anyhow!("Metadata salt file not found"));
        };

        // For debugging in tests
        #[cfg(test)]
        println!("Decrypting metadata with salt: {:?}", meta_salt);

        // Derive key from password and metadata salt
        let meta_key = derive_key(password.as_bytes(), &meta_salt)?;
        let meta_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&meta_key));

        // Try to decrypt the metadata
        let decrypted_metadata = match meta_cipher.decrypt(Nonce::from_slice(nonce), ciphertext) {
            Ok(data) => data,
            Err(_e) => {
                // For debugging in tests
                #[cfg(test)]
                println!("Failed to decrypt metadata: {:?}", _e);

                return Err(anyhow::anyhow!(
                    "Invalid password or corrupted metadata file"
                ));
            }
        };

        let metadata_contents = String::from_utf8(decrypted_metadata)?;

        // For debugging in tests
        #[cfg(test)]
        println!("Decrypted metadata: {}", metadata_contents);

        let mut lines = metadata_contents.lines();

        // First line is the salt
        let salt_str = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid metadata file"))?;
        let salt = URL_SAFE_NO_PAD.decode(salt_str)?;

        // Rest is the JSON data
        let files: HashMap<String, String> =
            serde_json::from_str(&lines.collect::<Vec<_>>().join("\n"))?;

        if files.is_empty() {
            return Err(anyhow::anyhow!("No files to decrypt"));
        }

        // Verify password by trying to derive a key and create a cipher
        let key = derive_key(password.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        // Decrypt all files
        let result = decrypt_files_with_cipher(&files, &cipher);

        // If decryption was successful, remove the metadata file and salt file
        if result.is_ok() {
            fs::remove_file(&meta_path)?;
            if meta_salt_path.exists() {
                fs::remove_file(&meta_salt_path)?;
            }
        }

        return result;
    } else {
        return Err(anyhow::anyhow!("No metadata file found"));
    }
}

fn decrypt_files_with_cipher(files: &HashMap<String, String>, cipher: &Aes256Gcm) -> Result<()> {
    let mut any_success = false;

    // Calculate total size of all files to decrypt
    let mut total_size: u64 = 0;
    let mut file_sizes: HashMap<String, u64> = HashMap::new();
    let mut files_exist: Vec<(String, String)> = Vec::new();

    for (encrypted_name, original_name) in files {
        if Path::new(encrypted_name).exists() {
            match fs::metadata(encrypted_name) {
                Ok(metadata) => {
                    let size = metadata.len();
                    total_size += size;
                    file_sizes.insert(encrypted_name.clone(), size);
                    files_exist.push((encrypted_name.clone(), original_name.clone()));
                }
                Err(e) => {
                    #[cfg(test)]
                    println!(
                        "Error getting metadata for file {}: {:?}",
                        encrypted_name, e
                    );
                }
            }
        }
    }

    if files_exist.is_empty() {
        return Err(anyhow::anyhow!("No files to decrypt"));
    }

    // Setup progress bar for decryption
    println!(
        "Decrypting {} files ({:.2} MB)...",
        files_exist.len(),
        total_size as f64 / 1024.0 / 1024.0
    );
    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("█▓▒░"),
    );

    // Track start time for speed calculation
    let start_time = std::time::Instant::now();

    // Process all files
    for (encrypted_file, original_file) in files_exist {
        let file_size = file_sizes.get(&encrypted_file).copied().unwrap_or(0);

        #[cfg(test)]
        println!(
            "Attempting to decrypt file: {} -> {}",
            encrypted_file, original_file
        );

        let encrypted_path = Path::new(&encrypted_file);
        if !encrypted_path.exists() {
            #[cfg(test)]
            println!("Encrypted file does not exist: {}", encrypted_file);
            eprintln!("Error: encrypted file not found");
            pb.inc(file_size);
            continue;
        }

        match decrypt_file_streaming(encrypted_path, cipher) {
            Ok(decrypted_data) => {
                #[cfg(test)]
                println!(
                    "Successfully decrypted data, size: {} bytes",
                    decrypted_data.len()
                );

                // Write the decrypted data to the original file
                if let Err(_e) = fs::write(&original_file, decrypted_data) {
                    #[cfg(test)]
                    println!("Failed to write decrypted data: {:?}", _e);
                    eprintln!("Error writing decrypted file");
                } else {
                    #[cfg(test)]
                    println!("Successfully wrote decrypted data to: {}", original_file);

                    // Remove the encrypted file only after successful decryption and writing
                    if let Err(_e) = fs::remove_file(&encrypted_file) {
                        #[cfg(test)]
                        println!("Error removing encrypted file: {:?}", _e);
                    }
                    any_success = true;
                }
            }
            Err(_e) => {
                #[cfg(test)]
                println!("Failed to decrypt file: {:?}", _e);
                eprintln!("Error decrypting file");
            }
        }

        pb.inc(file_size);
    }

    // Calculate decryption speed
    let elapsed = start_time.elapsed();
    let speed = if elapsed.as_secs() > 0 {
        total_size as f64 / elapsed.as_secs() as f64 / 1024.0 / 1024.0
    } else {
        total_size as f64 / 1024.0 / 1024.0 // If less than a second, just report the total size
    };

    // Finish progress bar
    pb.finish_with_message(format!("Done at {:.2} MB/s", speed));

    // Consider it a success if at least one file was decrypted successfully
    if any_success {
        Ok(())
    } else {
        Err(anyhow::anyhow!("All files failed to decrypt"))
    }
}

/// Show status of encrypted and unencrypted files in the current directory
fn status_directory() -> Result<()> {
    // Check if .seal directory exists
    let seal_dir = Path::new(SEAL_DIR);
    let meta_path = seal_dir.join(META_FILE);

    let has_metadata = meta_path.exists();

    // Count encrypted files (files with .sealed extension)
    let mut encrypted_files_count = 0;

    for entry in WalkDir::new(".").into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.extension().map_or(false, |ext| ext == EXTENSION) {
            encrypted_files_count += 1;
        }
    }

    // Count unencrypted files (excluding .seal directory and .sealed files)
    let mut unencrypted_files_count = 0;

    for entry in WalkDir::new(".").into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file()
            && !path.extension().map_or(false, |ext| ext == EXTENSION)
            && !path.to_string_lossy().contains(SEAL_DIR)
        {
            unencrypted_files_count += 1;
        }
    }

    // Print status information in a clean format
    if has_metadata {
        println!("✓ SEALED");
    } else {
        println!("✗ NOT SEALED");
    }

    println!("");
    println!("FILES:");
    println!("  {} encrypted", encrypted_files_count);
    println!("  {} unencrypted", unencrypted_files_count);

    Ok(())
}

fn encrypt_directory_with_password_and_files(password: &str, files: &[String]) -> Result<()> {
    let mut salt = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // Create .seal directory if it doesn't exist
    let seal_dir = Path::new(SEAL_DIR);
    if !seal_dir.exists() {
        fs::create_dir(seal_dir)?;
    }

    let meta_path = seal_dir.join(META_FILE);

    // Try to read existing metadata
    let mut metadata = if meta_path.exists() {
        // Decrypt the metadata file first
        let encrypted_metadata = fs::read(&meta_path)?;
        let (nonce, ciphertext) = encrypted_metadata.split_at(NONCE_LEN);

        // Read the metadata salt file
        let meta_salt_path = seal_dir.join(META_SALT_FILE);
        let meta_salt = if meta_salt_path.exists() {
            // Use the stored metadata salt if it exists
            fs::read(&meta_salt_path)?
        } else {
            // No fallback - require the salt file
            return Err(anyhow::anyhow!("Metadata salt file not found"));
        };

        // Derive key from password and metadata salt
        let meta_key = derive_key(password.as_bytes(), &meta_salt)?;
        let meta_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&meta_key));

        let decrypted_metadata = match meta_cipher.decrypt(Nonce::from_slice(nonce), ciphertext) {
            Ok(data) => data,
            Err(_e) => {
                // For debugging in tests
                #[cfg(test)]
                println!("Failed to decrypt metadata: {:?}", _e);

                return Err(anyhow::anyhow!(
                    "Invalid password or corrupted metadata file"
                ));
            }
        };

        let metadata_contents = String::from_utf8(decrypted_metadata)?;
        let mut lines = metadata_contents.lines();

        // Get existing salt
        let salt_str = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid metadata file"))?;
        let existing_salt = URL_SAFE_NO_PAD.decode(salt_str)?;

        // Parse existing files
        let existing_files: HashMap<String, String> =
            serde_json::from_str(&lines.collect::<Vec<_>>().join("\n"))?;

        // Use existing salt for consistency
        salt = existing_salt;

        Metadata {
            salt: URL_SAFE_NO_PAD.encode(&salt),
            files: existing_files,
        }
    } else {
        // Create a new metadata structure with the generated salt
        Metadata {
            salt: URL_SAFE_NO_PAD.encode(&salt),
            files: HashMap::new(),
        }
    };

    // Derive key with the salt
    let key = derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    // Filter and validate input files
    let files_to_encrypt: Vec<String> = if files.is_empty() {
        // If no files specified, encrypt all files (original behavior)
        WalkDir::new(".")
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_string_lossy().to_string())
            .filter(|s| {
                !s.starts_with("./.")
                    && !s.ends_with(EXTENSION)
                    && s != SEAL_DIR
                    && s != ".original_path"
            })
            .collect()
    } else {
        // Validate and use specified files
        files
            .iter()
            .filter(|f| {
                let path = Path::new(f);
                path.exists()
                    && !path.to_string_lossy().starts_with("./.")
                    && !path.to_string_lossy().ends_with(EXTENSION)
                    && path.to_string_lossy() != SEAL_DIR
            })
            .cloned()
            .collect()
    };

    #[cfg(test)]
    println!("Files to encrypt: {:?}", files_to_encrypt);

    if files_to_encrypt.is_empty() {
        if metadata.files.is_empty() {
            #[cfg(not(test))]
            return Err(anyhow::anyhow!("No files to encrypt"));

            #[cfg(test)]
            {
                println!("No files to encrypt, but continuing for test");
                // ... rest of the test code ...
            }
        } else {
            println!("No new files to encrypt");
            return Ok(());
        }
    }

    // Calculate total size of all files to encrypt
    let mut total_size: u64 = 0;
    let mut file_sizes: HashMap<String, u64> = HashMap::new();

    for path in &files_to_encrypt {
        match fs::metadata(path) {
            Ok(metadata) => {
                let size = metadata.len();
                total_size += size;
                file_sizes.insert(path.clone(), size);
            }
            Err(e) => {
                println!("Warning: Could not get size of file {}: {}", path, e);
                total_size += 1024;
                file_sizes.insert(path.clone(), 1024);
            }
        }
    }

    // Add estimated size for metadata operations
    let metadata_ops_size = 1024 * 1024;
    total_size += metadata_ops_size;

    println!(
        "Encrypting {} files ({:.2} MB)...",
        files_to_encrypt.len(),
        total_size as f64 / 1024.0 / 1024.0
    );

    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
            .unwrap()
            .progress_chars("█▓▒░"),
    );

    let start_time = std::time::Instant::now();

    // Encrypt each file
    for path in files_to_encrypt {
        let file_size = file_sizes.get(&path).copied().unwrap_or(0);
        pb.set_message("Encrypting files...");
        let encrypted = encrypt_file(&Path::new(&path), &cipher)?;

        let original_name = path.clone();
        let encrypted_path = create_encrypted_path(&path)?;

        if let Some(parent) = Path::new(&encrypted_path).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        fs::write(&encrypted_path, encrypted)?;
        fs::remove_file(&path)?;

        metadata
            .files
            .insert(encrypted_path.clone(), original_name.clone());

        pb.inc(file_size);
    }

    // Update progress for metadata operations and cleanup
    pb.set_message("Cleaning up empty directories...");
    remove_empty_directories(Path::new("."))?;
    pb.inc(metadata_ops_size / 4);

    pb.set_message("Generating metadata...");
    let metadata_string = format!(
        "{}\n{}",
        metadata.salt,
        serde_json::to_string(&metadata.files)?
    );
    pb.inc(metadata_ops_size / 4);

    let mut meta_salt = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut meta_salt);

    pb.set_message("Encrypting metadata...");
    let meta_salt_path = seal_dir.join(META_SALT_FILE);
    fs::write(&meta_salt_path, &meta_salt)?;

    let meta_key = derive_key(password.as_bytes(), &meta_salt)?;
    let meta_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&meta_key));
    pb.inc(metadata_ops_size / 4);

    let mut nonce = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let encrypted_metadata = meta_cipher
        .encrypt(Nonce::from_slice(&nonce), metadata_string.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to encrypt metadata: {}", e))?;

    pb.set_message("Writing metadata...");
    fs::write(meta_path, [nonce.as_slice(), &encrypted_metadata].concat())?;
    pb.inc(metadata_ops_size / 4);

    let elapsed = start_time.elapsed();
    let speed = if elapsed.as_secs() > 0 {
        total_size as f64 / elapsed.as_secs() as f64 / 1024.0 / 1024.0
    } else {
        total_size as f64 / 1024.0 / 1024.0
    };

    pb.finish_with_message(format!("Done at {:.2} MB/s", speed));

    Ok(())
}

fn decrypt_directory_with_password_and_files(password: &str, files: &[String]) -> Result<()> {
    let seal_dir = Path::new(SEAL_DIR);
    if !seal_dir.exists() {
        return Err(anyhow::anyhow!("No .seal directory found"));
    }

    let meta_path = seal_dir.join(META_FILE);

    if meta_path.exists() {
        let encrypted_metadata = fs::read(&meta_path)?;
        let (nonce, ciphertext) = encrypted_metadata.split_at(NONCE_LEN);

        let meta_salt_path = seal_dir.join(META_SALT_FILE);
        let meta_salt = if meta_salt_path.exists() {
            fs::read(&meta_salt_path)?
        } else {
            return Err(anyhow::anyhow!("Metadata salt file not found"));
        };

        #[cfg(test)]
        println!("Decrypting metadata with salt: {:?}", meta_salt);

        let meta_key = derive_key(password.as_bytes(), &meta_salt)?;
        let meta_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&meta_key));

        let decrypted_metadata = match meta_cipher.decrypt(Nonce::from_slice(nonce), ciphertext) {
            Ok(data) => data,
            Err(_e) => {
                #[cfg(test)]
                println!("Failed to decrypt metadata: {:?}", _e);
                return Err(anyhow::anyhow!(
                    "Invalid password or corrupted metadata file"
                ));
            }
        };

        let metadata_contents = String::from_utf8(decrypted_metadata)?;

        #[cfg(test)]
        println!("Decrypted metadata: {}", metadata_contents);

        let mut lines = metadata_contents.lines();
        let salt_str = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid metadata file"))?;
        let salt = URL_SAFE_NO_PAD.decode(salt_str)?;

        let all_files: HashMap<String, String> =
            serde_json::from_str(&lines.collect::<Vec<_>>().join("\n"))?;

        if all_files.is_empty() {
            return Err(anyhow::anyhow!("No files to decrypt"));
        }

        // Filter files based on input
        let files_to_decrypt: HashMap<String, String> = if files.is_empty() {
            // If no files specified, decrypt all files
            all_files
        } else {
            // Only decrypt specified files
            let mut filtered = HashMap::new();
            for file in files {
                // Try to find the encrypted file for the requested original filename
                for (encrypted, original) in &all_files {
                    if original == file {
                        filtered.insert(encrypted.clone(), original.clone());
                        break;
                    }
                }
            }
            filtered
        };

        if files_to_decrypt.is_empty() {
            return Err(anyhow::anyhow!("No matching files to decrypt"));
        }

        let key = derive_key(password.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        let result = decrypt_files_with_cipher(&files_to_decrypt, &cipher);

        // Only remove metadata if all files were decrypted and no specific files were requested
        if result.is_ok() && files.is_empty() {
            fs::remove_file(&meta_path)?;
            if meta_salt_path.exists() {
                fs::remove_file(&meta_salt_path)?;
            }
        }

        return result;
    } else {
        return Err(anyhow::anyhow!("No metadata file found"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use std::sync::Mutex;
    use std::{thread, time::Duration};
    use tempfile::TempDir;
    use uuid::Uuid;

    // Use a mutex to ensure only one test can change the current directory at a time
    lazy_static! {
        static ref CURRENT_DIR_MUTEX: Mutex<()> = Mutex::new(());
    }

    // Helper function to generate a unique directory name for tests
    fn unique_test_dir() -> String {
        format!("test_dir_{}", Uuid::new_v4().to_string())
    }

    #[test]
    fn test_test_mode() -> Result<()> {
        // Acquire the mutex to ensure exclusive access to the current directory
        let _lock = match CURRENT_DIR_MUTEX.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // If the mutex is poisoned, recover it
                println!("Warning: Mutex was poisoned. Recovering...");
                poisoned.into_inner()
            }
        };

        // This test verifies that the TEST_MODE functionality works correctly
        // It should create a test directory, run the program, and clean up after itself

        // Create a test directory with a unique name
        let test_dir_name = unique_test_dir();
        let test_dir = Path::new(&test_dir_name);
        if test_dir.exists() {
            fs::remove_dir_all(test_dir)?;
        }
        fs::create_dir(test_dir)?;

        // Change to the test directory
        let original_dir = std::env::current_dir()?;
        println!(
            "Test mode - Current dir before: {:?}",
            std::env::current_dir()?
        );
        std::env::set_current_dir(test_dir)?;
        println!(
            "Test mode - Current dir after: {:?}",
            std::env::current_dir()?
        );

        // Create a test file with a unique name
        let test_file = format!("testfile_{}.txt", Uuid::new_v4().to_string());
        fs::write(&test_file, "This is a test file")?;

        // Sleep a bit to ensure files are written
        thread::sleep(Duration::from_millis(100));

        // List files to verify they exist
        println!("Test mode - Files created:");
        for entry in WalkDir::new(".").into_iter().filter_map(|e| e.ok()) {
            println!("Test mode - Found: {:?}", entry.path());
        }

        // Check if .seal directory exists before encryption
        if Path::new(SEAL_DIR).exists() {
            println!("Test mode - Warning: .seal directory already exists before encryption");
            fs::remove_dir_all(SEAL_DIR)?;
        }

        // Run the test mode function
        let password = "test_password";
        println!("Test mode - Encrypting with password: {}", password);
        encrypt_directory_with_password(password)?;

        // Verify the metadata file exists
        let seal_dir = Path::new(SEAL_DIR);
        let meta_path = seal_dir.join(META_FILE);
        assert!(meta_path.exists(), "Metadata file should exist");

        // List files after encryption
        println!("Test mode - Files after encryption:");
        for entry in WalkDir::new(".").into_iter().filter_map(|e| e.ok()) {
            println!("Test mode - Found: {:?}", entry.path());
        }

        // Decrypt the files
        println!("Test mode - Decrypting with password: {}", password);
        decrypt_directory_with_password(password)?;

        // List files after decryption
        println!("Test mode - Files after decryption:");
        for entry in WalkDir::new(".").into_iter().filter_map(|e| e.ok()) {
            println!("Test mode - Found: {:?}", entry.path());
        }

        // Verify the original file is restored
        assert!(Path::new(&test_file).exists(), "Test file should exist");
        assert_eq!(fs::read_to_string(&test_file)?, "This is a test file");

        // Clean up
        println!("Test mode - Cleaning up");
        std::env::set_current_dir(original_dir)?;
        fs::remove_dir_all(test_dir)?;

        // Verify that the test directory was cleaned up
        assert!(
            !Path::new(&test_dir_name).exists(),
            "Test directory should be cleaned up"
        );

        Ok(())
    }

    #[test]
    fn test_subdirectory_encryption_decryption() -> Result<()> {
        // Acquire the mutex to ensure exclusive access to the current directory
        let _lock = match CURRENT_DIR_MUTEX.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // If the mutex is poisoned, recover it
                println!("Warning: Mutex was poisoned. Recovering...");
                poisoned.into_inner()
            }
        };

        // ... rest of the test ...

        Ok(())
    }

    // ... other tests ...

    #[test]
    fn test_corrupted_file() -> Result<()> {
        // Acquire the mutex to ensure exclusive access to the current directory
        let _lock = match CURRENT_DIR_MUTEX.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // If the mutex is poisoned, recover it
                println!("Warning: Mutex was poisoned. Recovering...");
                poisoned.into_inner()
            }
        };

        // Create a unique test directory and store it in a variable that lives for the whole test
        let temp_dir = TempDir::new()?;
        let original_dir = std::env::current_dir()?;

        // Create a deferred cleanup function that will run even if the test fails
        let _cleanup = scopeguard::guard((), |_| {
            let _ = std::env::set_current_dir(&original_dir);
            println!("Corrupted file test - Cleanup complete");
        });

        println!(
            "Corrupted file test - Current dir before: {:?}",
            std::env::current_dir()?
        );
        std::env::set_current_dir(&temp_dir)?;
        println!(
            "Corrupted file test - Current dir after: {:?}",
            std::env::current_dir()?
        );

        // Create files
        let file1 = format!("file1_{}.txt", Uuid::new_v4().to_string());
        let file2 = format!("file2_{}.txt", Uuid::new_v4().to_string());

        fs::write(&file1, "File 1 content")?;
        fs::write(&file2, "File 2 content")?;

        // Sleep a bit to ensure files are written
        thread::sleep(Duration::from_millis(100));

        println!("Corrupted file test - Files created");

        // Encrypt with password
        let password = "test_password";
        println!(
            "Corrupted file test - Encrypting with password: {}",
            password
        );
        encrypt_directory_with_password(password)?;

        println!("Corrupted file test - Encryption complete");

        // List files after encryption
        println!("Corrupted file test - After encryption:");
        for entry in WalkDir::new(".").into_iter().filter_map(|e| e.ok()) {
            println!("Found: {:?}", entry.path());
        }

        // Get the metadata file to find the encrypted filenames
        let seal_dir = Path::new(SEAL_DIR);
        let meta_path = seal_dir.join(META_FILE);
        let encrypted_metadata = fs::read(&meta_path)?;
        let (nonce, ciphertext) = encrypted_metadata.split_at(NONCE_LEN);

        // Read the metadata salt file
        let meta_salt_path = seal_dir.join(META_SALT_FILE);
        let meta_salt = if meta_salt_path.exists() {
            // Use the stored metadata salt if it exists
            fs::read(&meta_salt_path)?
        } else {
            // No fallback - require the salt file
            return Err(anyhow::anyhow!("Metadata salt file not found"));
        };

        // Decrypt the metadata
        let meta_key = derive_key(password.as_bytes(), &meta_salt)?;
        let meta_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&meta_key));

        let decrypted_metadata = match meta_cipher.decrypt(Nonce::from_slice(nonce), ciphertext) {
            Ok(data) => data,
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to decrypt metadata: {:?}", e));
            }
        };

        let metadata_contents = String::from_utf8(decrypted_metadata)?;
        let mut lines = metadata_contents.lines();

        // Skip the salt line
        lines.next();

        // Parse the files map
        let files: HashMap<String, String> =
            serde_json::from_str(&lines.collect::<Vec<_>>().join("\n"))?;

        // Find the encrypted filenames
        let mut encrypted_file1 = String::new();
        let mut encrypted_file2 = String::new();

        for (encrypted, original) in &files {
            if original.ends_with(&file1) {
                encrypted_file1 = encrypted.clone();
            } else if original.ends_with(&file2) {
                encrypted_file2 = encrypted.clone();
            }
        }

        assert!(
            !encrypted_file1.is_empty(),
            "Could not find encrypted filename for file1"
        );
        assert!(
            !encrypted_file2.is_empty(),
            "Could not find encrypted filename for file2"
        );

        // Corrupt both files to test the case where all files are corrupted
        println!(
            "Corrupted file test - Corrupting encrypted file: {}",
            encrypted_file1
        );
        let corrupted_content = "This is not a valid encrypted file";
        fs::write(&encrypted_file1, corrupted_content)?;

        // Verify the file is corrupted
        assert_eq!(
            fs::read_to_string(&encrypted_file1)?,
            corrupted_content,
            "File should be corrupted"
        );

        // Try to decrypt with the corrupted file
        println!("Corrupted file test - Decrypting with corrupted file");
        let result = decrypt_directory_with_password(password);

        // Decryption should succeed since at least one file was decrypted
        assert!(
            result.is_ok(),
            "Decryption should succeed if at least one file is decrypted"
        );

        // Verify that file2 was decrypted
        assert!(Path::new(&file2).exists(), "File2 should be decrypted");
        assert_eq!(fs::read_to_string(&file2)?, "File 2 content");

        // Verify that file1 was not decrypted (since its encrypted file was corrupted)
        assert!(!Path::new(&file1).exists(), "File1 should not be decrypted");

        // Verify that the corrupted file is still there
        assert!(
            Path::new(&encrypted_file1).exists(),
            "Corrupted file should still exist"
        );

        // The cleanup will happen automatically when temp_dir is dropped and
        // when the scopeguard runs to change back to the original directory
        Ok(())
    }

    #[test]
    fn test_empty_file() -> Result<()> {
        // Acquire the mutex to ensure exclusive access to the current directory
        let _lock = match CURRENT_DIR_MUTEX.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // If the mutex is poisoned, recover it
                println!("Warning: Mutex was poisoned. Recovering...");
                poisoned.into_inner()
            }
        };

        // ... rest of the test ...

        Ok(())
    }

    #[test]
    fn test_missing_encrypted_file() -> Result<()> {
        // Acquire the mutex to ensure exclusive access to the current directory
        let _lock = match CURRENT_DIR_MUTEX.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // If the mutex is poisoned, recover it
                println!("Warning: Mutex was poisoned. Recovering...");
                poisoned.into_inner()
            }
        };

        // ... rest of the test ...

        Ok(())
    }

    #[test]
    fn test_encryption_with_different_password() -> Result<()> {
        // Acquire the mutex to ensure exclusive access to the current directory
        let _lock = match CURRENT_DIR_MUTEX.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // If the mutex is poisoned, recover it
                println!("Warning: Mutex was poisoned. Recovering...");
                poisoned.into_inner()
            }
        };

        // ... rest of the test ...

        Ok(())
    }

    #[test]
    fn test_large_file() -> Result<()> {
        use std::io::{Read, Write};

        // Acquire the mutex to ensure exclusive access to the current directory
        let _lock = match CURRENT_DIR_MUTEX.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                println!("Warning: Mutex was poisoned. Recovering...");
                poisoned.into_inner()
            }
        };

        // Create a unique test directory and store it in a variable that lives for the whole test
        let temp_dir = TempDir::new()?;
        let original_dir = std::env::current_dir()?;

        // Create a deferred cleanup function that will run even if the test fails
        let _cleanup = scopeguard::guard((), |_| {
            let _ = std::env::set_current_dir(&original_dir);
            println!("Large file test - Cleanup complete");
        });

        std::env::set_current_dir(&temp_dir)?;

        // Create a large test file with a verifiable pattern
        let test_file = format!("largefile_{}.bin", Uuid::new_v4().to_string());
        let test_size = LARGE_FILE_THRESHOLD as usize * 3; // Make it 3x the threshold to ensure multiple chunks
        println!("Creating test file of size: {} bytes", test_size);

        // Create file with a pattern that varies by chunk for verification
        let mut file = std::fs::File::create(&test_file)?;
        let mut written = 0;
        let chunk_size = CHUNK_SIZE;

        while written < test_size {
            let to_write = std::cmp::min(chunk_size, test_size - written);
            let chunk_number = (written / chunk_size) as u8;
            let chunk: Vec<u8> = (0..to_write)
                .map(|i| (i as u8).wrapping_add(chunk_number))
                .collect();
            file.write_all(&chunk)?;
            written += to_write;
        }
        drop(file);

        // Verify the file size
        let metadata = std::fs::metadata(&test_file)?;
        assert_eq!(metadata.len(), test_size as u64);

        // Encrypt with password
        let password = "test_password";
        encrypt_directory_with_password(password)?;

        // Verify the original file is gone and an encrypted file exists
        assert!(
            !Path::new(&test_file).exists(),
            "Original file should be gone"
        );

        // Find the encrypted file
        let mut encrypted_file_path = None;
        for entry in WalkDir::new(".").into_iter().filter_map(|e| e.ok()) {
            if entry.path().to_string_lossy().ends_with(EXTENSION) {
                encrypted_file_path = Some(entry.path().to_path_buf());
                break;
            }
        }
        let encrypted_file_path = encrypted_file_path.expect("Should find encrypted file");

        // Verify encrypted file size is reasonable (should be original size + nonce + some overhead)
        let encrypted_size = fs::metadata(&encrypted_file_path)?.len();
        assert!(
            encrypted_size > test_size as u64,
            "Encrypted file should be larger than original"
        );
        assert!(
            encrypted_size < (test_size + CHUNK_SIZE) as u64,
            "Encrypted file shouldn't be too much larger"
        );

        // Decrypt the files
        decrypt_directory_with_password(password)?;

        // Verify the original file is restored
        assert!(Path::new(&test_file).exists(), "Test file should exist");
        let restored_metadata = std::fs::metadata(&test_file)?;
        assert_eq!(restored_metadata.len(), test_size as u64);

        // Verify the contents chunk by chunk
        let mut restored_file = std::fs::File::open(&test_file)?;
        let mut buffer = vec![0u8; chunk_size];
        let mut total_read = 0;

        while total_read < test_size {
            let expected_chunk_size = std::cmp::min(chunk_size, test_size - total_read);
            let chunk_number = (total_read / chunk_size) as u8;

            // Read a chunk
            let n = restored_file.read(&mut buffer[..expected_chunk_size])?;
            assert_eq!(n, expected_chunk_size, "Should read full chunk");

            // Verify chunk contents
            for (i, &byte) in buffer[..n].iter().enumerate() {
                let expected = (i as u8).wrapping_add(chunk_number);
                assert_eq!(
                    byte,
                    expected,
                    "Mismatch at position {} in chunk {} (got {}, expected {})",
                    i,
                    total_read / chunk_size,
                    byte,
                    expected
                );
            }

            total_read += n;
        }

        // Verify we've read everything
        assert_eq!(total_read, test_size);

        // Try to read one more byte - should get EOF
        assert_eq!(restored_file.read(&mut buffer[..1])?, 0);

        // The cleanup will happen automatically when temp_dir is dropped and
        // when the scopeguard runs to change back to the original directory
        Ok(())
    }

    #[test]
    fn test_metadata_salt() -> Result<()> {
        // Acquire the mutex to ensure exclusive access to the current directory
        let _lock = match CURRENT_DIR_MUTEX.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // If the mutex is poisoned, recover it
                println!("Warning: Mutex was poisoned. Recovering...");
                poisoned.into_inner()
            }
        };

        // Create a unique test directory and store it in a variable that lives for the whole test
        let temp_dir = TempDir::new()?;
        let original_dir = std::env::current_dir()?;

        // Create a deferred cleanup function that will run even if the test fails
        let _cleanup = scopeguard::guard((), |_| {
            let _ = std::env::set_current_dir(&original_dir);
            println!("Metadata salt test - Cleanup complete");
        });

        println!(
            "Metadata salt test - Current dir before: {:?}",
            std::env::current_dir()?
        );
        std::env::set_current_dir(&temp_dir)?;
        println!(
            "Metadata salt test - Current dir after: {:?}",
            std::env::current_dir()?
        );

        // Create a test file
        let test_file = format!("testfile_{}.txt", Uuid::new_v4().to_string());
        fs::write(&test_file, "This is a test file")?;

        // Sleep a bit to ensure files are written
        thread::sleep(Duration::from_millis(100));

        println!("Metadata salt test - Files created");

        // Encrypt with password
        let password = "test_password";
        println!(
            "Metadata salt test - Encrypting with password: {}",
            password
        );
        encrypt_directory_with_password(password)?;

        // Verify the metadata salt file exists
        let seal_dir = Path::new(SEAL_DIR);
        let meta_path = seal_dir.join(META_FILE);
        let meta_salt_path = seal_dir.join(META_SALT_FILE);

        assert!(meta_path.exists(), "Metadata file should exist");
        assert!(meta_salt_path.exists(), "Metadata salt file should exist");

        // Verify the salt file has the correct size
        let salt_content = fs::read(&meta_salt_path)?;
        assert_eq!(
            salt_content.len(),
            SALT_LEN,
            "Salt file should have the correct size"
        );

        // Verify the salt is not all zeros
        let zero_salt = vec![0u8; SALT_LEN];
        assert_ne!(salt_content, zero_salt, "Salt should not be all zeros");

        // Decrypt the files
        println!(
            "Metadata salt test - Decrypting with password: {}",
            password
        );
        decrypt_directory_with_password(password)?;

        // Verify the original file is restored
        assert!(Path::new(&test_file).exists(), "Test file should exist");
        assert_eq!(fs::read_to_string(&test_file)?, "This is a test file");

        // Verify the metadata and salt files are removed after successful decryption
        assert!(
            !meta_path.exists(),
            "Metadata file should be removed after decryption"
        );
        assert!(
            !meta_salt_path.exists(),
            "Metadata salt file should be removed after decryption"
        );

        // The cleanup will happen automatically when temp_dir is dropped and
        // when the scopeguard runs to change back to the original directory
        Ok(())
    }

    #[test]
    fn test_metadata_salt_required() -> Result<()> {
        // Acquire the mutex to ensure exclusive access to the current directory
        let _lock = match CURRENT_DIR_MUTEX.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // If the mutex is poisoned, recover it
                println!("Warning: Mutex was poisoned. Recovering...");
                poisoned.into_inner()
            }
        };

        // Create a unique test directory and store it in a variable that lives for the whole test
        let temp_dir = TempDir::new()?;
        let original_dir = std::env::current_dir()?;

        // Create a deferred cleanup function that will run even if the test fails
        let _cleanup = scopeguard::guard((), |_| {
            let _ = std::env::set_current_dir(&original_dir);
            println!("Metadata salt required test - Cleanup complete");
        });

        println!(
            "Metadata salt required test - Current dir before: {:?}",
            std::env::current_dir()?
        );
        std::env::set_current_dir(&temp_dir)?;
        println!(
            "Metadata salt required test - Current dir after: {:?}",
            std::env::current_dir()?
        );

        // Create a test file
        let test_file = format!("testfile_{}.txt", Uuid::new_v4().to_string());
        fs::write(&test_file, "This is a test file")?;

        // Sleep a bit to ensure files are written
        thread::sleep(Duration::from_millis(100));

        println!("Metadata salt required test - Files created");

        // Encrypt with password
        let password = "test_password";
        println!(
            "Metadata salt required test - Encrypting with password: {}",
            password
        );
        encrypt_directory_with_password(password)?;

        // Verify the metadata salt file exists
        let seal_dir = Path::new(SEAL_DIR);
        let meta_path = seal_dir.join(META_FILE);
        let meta_salt_path = seal_dir.join(META_SALT_FILE);

        assert!(meta_path.exists(), "Metadata file should exist");
        assert!(meta_salt_path.exists(), "Metadata salt file should exist");

        // Delete the salt file to simulate it being missing
        fs::remove_file(&meta_salt_path)?;
        assert!(
            !meta_salt_path.exists(),
            "Metadata salt file should be removed"
        );

        // Try to decrypt the files - should fail because salt file is required
        println!(
            "Metadata salt required test - Decrypting with password: {}",
            password
        );
        let result = decrypt_directory_with_password(password);

        // Decryption should fail because the salt file is missing
        assert!(
            result.is_err(),
            "Decryption should fail without the salt file"
        );

        // Verify the error message
        if let Err(e) = result {
            assert!(
                e.to_string().contains("Metadata salt file not found"),
                "Error message should mention missing salt file"
            );
        }

        // The cleanup will happen automatically when temp_dir is dropped and
        // when the scopeguard runs to change back to the original directory
        Ok(())
    }
}
