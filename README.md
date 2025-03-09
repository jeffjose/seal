# Seal

Seal is a simple, secure file encryption tool that makes it easy to protect your sensitive files. It uses AES-256-GCM encryption with Argon2 key derivation to ensure your data remains private.


## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/seal.git
cd seal

# Build the project
cargo build --release

# Optional: Move the binary to your PATH
cp target/release/seal /usr/local/bin/
```

## Usage

### Encrypt Files

To encrypt all files in the current directory and subdirectories:

```bash
seal encrypt
# or the shorter alias
seal e
```

You'll be prompted for a password. Make sure to remember this password, as you'll need it to decrypt your files later!

### Decrypt Files

To decrypt previously encrypted files:

```bash
seal decrypt
# or the shorter aliases
seal d
seal x
```

You'll be prompted for the password you used during encryption.

### Check Status

To check the encryption status of your directory:

```bash
seal status
# or the shorter alias
seal st
```

This will show you:

- Whether the directory is sealed (has encryption metadata)
- Number of encrypted files
- Number of unencrypted files

### Password Options

You can provide a password directly using the `-p` or `--password` option:

```bash
seal encrypt --password "your-password-here"
```

**Note**: This is less secure as the password may be visible in your command history.

## How It Works

1. When you encrypt files, Seal:

   - Creates a `.seal` directory to store metadata
   - Generates a random salt for key derivation
   - Derives an encryption key from your password using Argon2
   - Encrypts each file with AES-256-GCM
   - Renames encrypted files to random, friendly names
   - Stores the mapping between original and encrypted filenames

2. When you decrypt files, Seal:
   - Reads the metadata from the `.seal` directory
   - Derives the decryption key from your password
   - Decrypts each file and restores its original name
   - Removes the encrypted files

## Security Considerations

- Your password is never stored; only a salt is saved in the metadata
- Files are encrypted individually with unique nonces
- The tool handles corrupted files gracefully, allowing you to decrypt the rest of your files even if some are damaged

## License

[MIT License](LICENSE)
