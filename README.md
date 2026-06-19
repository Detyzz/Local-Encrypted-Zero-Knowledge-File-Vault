# Local Encrypted Zero-Knowledge File Vault

A small command-line file vault that encrypts and decrypts files locally with AES-256-GCM authenticated encryption. The encryption key is derived from a master password with PBKDF2-HMAC-SHA256, and the plaintext never needs to leave your machine.

> Educational security project: this demonstrates practical cryptography, file handling, authenticated encryption, and password-based key derivation. It is not a replacement for a professionally audited password manager or enterprise vault.

## Features

- Encrypt any local file with AES-256-GCM
- Decrypt only when the correct master password is provided
- Detect tampering with GCM authentication tags
- Derive a 256-bit encryption key from a password using PBKDF2-HMAC-SHA256
- Use a fresh random salt and nonce for every encryption
- Stream files in chunks instead of loading the whole file into memory
- Write decrypted data to a temporary file first, then replace the final output only after authentication succeeds
- Best-effort wiping of mutable password and key buffers

## Project Structure

```text
.
├── vault.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10 or newer
- `cryptography` Python package

## Setup

1. Clone your repository and open the project folder.

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

2. Create a virtual environment.

```bash
python -m venv .venv
```

3. Activate the virtual environment.

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS or Linux:

```bash
source .venv/bin/activate
```

4. Install dependencies.

```bash
pip install -r requirements.txt
```

## Usage

### Encrypt a file

```bash
python vault.py encrypt secrets.txt
```

You will be asked to enter and confirm a master password. The encrypted file will be saved as:

```text
secrets.txt.zvault
```

### Decrypt a file

```bash
python vault.py decrypt secrets.txt.zvault
```

You will be asked for the master password. If the password is correct and the file has not been modified, the original file will be restored as:

```text
secrets.txt
```

### Choose a custom output path

```bash
python vault.py encrypt secrets.txt --output encrypted-backup.zvault
python vault.py decrypt encrypted-backup.zvault --output restored-secrets.txt
```

### Overwrite an existing output file

By default, the vault refuses to overwrite files. Use `--force` when you intentionally want to replace the output file.

```bash
python vault.py encrypt secrets.txt --output backup.zvault --force
python vault.py decrypt backup.zvault --output secrets.txt --force
```

### Increase PBKDF2 work factor

The default is 600,000 PBKDF2 iterations. You can increase this if your machine can handle the extra delay.

```bash
python vault.py encrypt secrets.txt --iterations 1000000
```

## How It Works

1. The program asks for a master password without displaying it on screen.
2. It generates a random 16-byte salt.
3. PBKDF2-HMAC-SHA256 derives a 32-byte key from the password and salt.
4. It generates a random 12-byte AES-GCM nonce.
5. AES-256-GCM encrypts the file and produces an authentication tag.
6. The encrypted output stores a small header, ciphertext, and authentication tag.
7. During decryption, AES-GCM verifies the tag before the temporary plaintext file becomes the final output.

Encrypted file format:

```text
MAGIC(4 bytes) | PBKDF2_ITERATIONS(4 bytes) | SALT(16 bytes) | NONCE(12 bytes) | CIPHERTEXT | TAG(16 bytes)
```

The header is authenticated as AES-GCM additional authenticated data, so changing the stored salt, nonce, or iteration count causes decryption to fail.

## Security Notes

- Use a long, unique master password. A weak password can still be guessed offline.
- The program uses fresh random salt and nonce values for every encryption.
- AES-GCM provides confidentiality and integrity, meaning modified ciphertext should fail decryption.
- Python cannot guarantee perfect memory wiping because immutable strings and internal copies may exist. This project performs best-effort wiping for mutable password and key buffers.
- Do not commit real secrets, plaintext files, or encrypted files containing sensitive data to public repositories.

## Quick Test

Create a sample file:

```bash
echo "top secret message" > message.txt
```

Encrypt it:

```bash
python vault.py encrypt message.txt
```

Decrypt it to a new file:

```bash
python vault.py decrypt message.txt.zvault --output restored-message.txt
```

Compare the files:

Windows PowerShell:

```powershell
Compare-Object (Get-Content message.txt) (Get-Content restored-message.txt)
```

macOS or Linux:

```bash
diff message.txt restored-message.txt
```

No output means the files match.

## License

MIT License. You can replace this section with your preferred license file before publishing.
