# RSA Encrypter/Decrypter CLI

This is a minimal command-line tool to encrypt and decrypt messages using RSA public/private key pairs. It supports multiple key pairs stored in a directory, automatically tries all private keys for decryption, and is compatible with standard OpenSSL PEM-format keys. It uses Node.js and the native `crypto` module only.

Supports both direct strings and file inputs, and outputs either raw text or JSON metadata.

## Getting Started

You can replace `KEY_NAME_HERE` with what you want to call your key

### 1. Generate RSA Keys

#### Private Key (2048-bit)
```bash
openssl genpkey -algorithm RSA -out KEY_NAME_HERE.priv.pem -pkeyopt rsa_keygen_bits:2048
```

#### Public Key (can generate multiple)
```bash
openssl rsa -pubout -in KEY_NAME_HERE.priv.pem -out KEY_NAME_HERE.pub.pem
```

Place these files in your key directory, e.g. `~/.keys/`.

- Keys must follow the naming pattern:  
  `KEY_NAME_HERE.pub.pem` for public keys  
  `KEY_NAME_HERE.priv.pem` for private keys

### 2. Encrypt a message

Encrypt a message using the first or a specific public key:
```bash
node index.js --encrypt --key-id KEY_NAME_HERE --plaintext "my secret" -o encrypted.txt
```

Or:
```bash
node index.js -e -ptf message.txt -id KEY_NAME_HERE
```

### 3. Decrypt a message

Decrypt from a base64 string:
```bash
node index.js --cypher-text "..." 
```

Decrypt from a file and write output to a JSON file:
```bash
node index.js --cypher-text-file encrypted.txt --output result.json
```

Decrypt to raw plaintext only:
```bash
node index.js --cypher-text-file encrypted.txt --raw
```

## Full Usage

### Environment Variables

These can be used instead of CLI flags. CLI flags take precedence.

| Variable             | Default         | Description                               |
|----------------------|------------------|-------------------------------------------|
| `KEYS`               | `~/.keys`        | Directory to load key pairs from          |
| `MODE`               | `decrypt`        | Either `encrypt` or `decrypt`             |
| `KEY_ID`             | *(optional)*     | Public key name to use when encrypting    |
| `OUTPUT`             | *(optional)*     | File to write output                      |
| `PLAINTEXT`          | *(optional)*     | Plaintext string to encrypt               |
| `PLAINTEXT_FILE`     | *(optional)*     | File path containing plaintext            |
| `CIPHER_TEXT`        | *(optional)*     | Ciphertext string to decrypt              |
| `CIPHER_TEXT_FILE`   | *(optional)*     | File path containing ciphertext           |

### CLI Flags

| Flag                           | Description                                 |
|--------------------------------|---------------------------------------------|
| `--encrypt`, `-e`              | Enable encryption mode                      |
| `--decrypt`, `-d`              | Enable decryption mode (default)            |
| `--keys <path>`, `-k <path>`   | Override key directory                      |
| `--key-id <id>`, `-id <id>`    | Public key ID to use when encrypting        |
| `--output <file>`, `-o <file>` | File to write output                        |
| `--cypher-text <str>`, `-ct`   | Ciphertext string to decrypt                |
| `--cypher-text-file <file>`    | Ciphertext file to decrypt                  |
| `--plaintext <str>`, `-pt`     | Plaintext string to encrypt                 |
| `--plaintext-file <file>`      | Plaintext file to encrypt                   |
| `--raw`                        | Output raw plaintext (no JSON)              |
| `--help`, `-h`                 | Show help menu                              |

## Output

By default, decryption results are printed as JSON:
```json
{
  "keyId": "main",
  "padding": 4,
  "hash": "sha256",
  "output": "decrypted message here"
}
```

Use `--raw` to print only the plaintext.

## Online Tools (Use With Caution)

Use these tools for testing only. Do not paste private keys into these websites.

- Generate keys (Java-based): https://www.devglan.com/online-tools/rsa-encryption-decryption  
- Encrypt/decrypt in browser (Node-compatible): https://emn178.github.io/online-tools/rsa/encrypt  
  Be sure to select **SHA256** when encrypting. The default option will not work with Node.js.

## Security Notice

Never share or expose your private keys. Store them securely and offline whenever possible. This tool uses standard RSA encryption but should not be considered secure without proper key handling practices.
