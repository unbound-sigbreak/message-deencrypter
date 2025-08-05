#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const RSACrypto = require('./rsa-crypto');

let mode = 'decrypt';
let keyDir = path.join(os.homedir(), '.keys');
let ciphertext = null;
let plaintext = null;
let keyId = null;
let outputPath = null;
let outputRaw = false;
let useAES = false;

let ciphertextSource = null;
let plaintextSource = null;

const printHelp = () => {
  console.log(`RSA Encrypter/Decrypter CLI`);
  console.log('');
  console.log(`  Defaults to decryption mode unless --encrypt is specified`);
  console.log('');
  console.log(`Usage [Environment Variables]:`);
  console.log(`  * KEYS                = {"~/.keys"}     - Key directory`);
  console.log(`  * MODE                = {"decrypt"}     - Operation: "encrypt" or "decrypt"`);
  console.log(`  * KEY_ID              = {empty}         - Key ID to encrypt with`);
  console.log(`  * OUTPUT              = {empty}         - Output file`);
  console.log(`  * PLAINTEXT           = {empty}         - Plaintext string (for encryption)`);
  console.log(`  * PLAINTEXT_FILE      = {empty}         - File path to plaintext input`);
  console.log(`  * CIPHER_TEXT         = {empty}         - Ciphertext string (for decryption)`);
  console.log(`  * CIPHER_TEXT_FILE    = {empty}         - File path to ciphertext input`);
  console.log('');
  console.log(`Usage [CLI Flags]:`);
  console.log(`  * --encrypt, -e                      - Set mode to encrypt`);
  console.log(`  * --decrypt, -d                      - Set mode to decrypt (default)`);
  console.log(`  * --keys, -k         [path]          - Override key directory`);
  console.log(`  * --key-id, -id      [id]            - Specific key to encrypt with`);
  console.log(`  * --output, -o       [file]          - Output file to write result`);
  console.log(`  * --cypher-text, -ct  [string]       - Ciphertext to decrypt`);
  console.log(`  * --cypher-text-file, -ctf [file]    - Ciphertext file`);
  console.log(`  * --plaintext, -pt     [string]      - Plaintext to encrypt`);
  console.log(`  * --plaintext-file, -ptf [file]      - Plaintext file`);
  console.log(`  * --aes                              - Enable hybrid AES+RSA encryption. Required for encrypting long messages.`);
  console.log(`  * --raw                              - Output raw plaintext (no JSON)`);
  console.log(`  * --help, -h                         - Show this help`);
  console.log('');
  
  console.log('Generate keys online (unsafe):                  https://www.devglan.com/online-tools/rsa-encryption-decryption');
  console.log('Encrypt and Decrypt (unsafe) with keys online:  https://emn178.github.io/online-tools/rsa/encrypt');
  console.log('    Be sure to select SHA256 when encrypting your text. The default option will not work.');
  console.log('');

  console.log('Generate keys locally:');
  console.log(`Private key:`);
  console.log(`$ openssl genpkey -algorithm RSA -out KEY_NAME_HERE.priv.pem -pkeyopt rsa_keygen_bits:2048`);

  console.log(`Public key (can generate many):`);
  console.log(`$ openssl rsa -pubout -in KEY_NAME_HERE.priv.pem -out KEY_NAME_HERE.pub.pem`);
  console.log('');
  console.log('--- NEVER SHARE YOUR PRIVATE KEY. DO NOT PUT IT ONLINE ---');
  console.log('');

  console.log('');
  console.log('Examples:')
  console.log(`Decrypt base64 string`);
  console.log(`$ node cli.js --cypher-text "..."`);

  console.log(`Encrypt and save to file`);
  console.log(`$ node cli.js -e --key-id KEY_NAME_HERE --plaintext "secret" -o out.txt`);

  console.log(`Decrypt from file, output to JSON`);
  console.log(`$ node cli.js -ctf encrypted.txt -o result.json`);
  console.log('');
};

const parseArgs = (argv) => {
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);

      case '--encrypt':
      case '-e':
        mode = 'encrypt';
        break;

      case '--decrypt':
      case '-d':
        mode = 'decrypt';
        break;

      case '--keys':
      case '-k':
        keyDir = argv[i + 1];
        i++;
        break;

      case '--key-id':
      case '-id':
        keyId = argv[i + 1];
        i++;
        break;

      case '--output':
      case '-o':
        outputPath = argv[i + 1];
        i++;
        break;

      case '--cypher-text':
      case '-ct':
        ciphertext = argv[i + 1];
        ciphertextSource = 'direct';
        i++;
        break;

      case '--cypher-text-file':
      case '-ctf':
        ciphertext = fs.readFileSync(argv[i + 1], 'utf8');
        ciphertextSource = 'file';
        i++;
        break;

      case '--plaintext':
      case '-pt':
        plaintext = argv[i + 1];
        plaintextSource = 'direct';
        i++;
        break;

      case '--raw':
        outputRaw = true;
        break;

      case '--aes':
        useAES = true;
        break;

      case '--plaintext-file':
      case '-ptf':
        plaintext = fs.readFileSync(argv[i + 1], 'utf8');
        plaintextSource = 'file';
        i++;
        break;
    }
  }
};

parseArgs(process.argv.slice(2));

// ENV fallback
if (process.env.DEEC_KEYS) keyDir = process.env.DEEC_KEYS;
if (process.env.DEEC_MODE) mode = process.env.DEEC_MODE;
if (process.env.DEEC_KEY_ID) keyId = process.env.DEEC_KEY_ID;
if (process.env.DEEC_OUTPUT) outputPath = process.env.DEEC_OUTPUT;
if (process.env.DEEC_AES === 'true') useAES = true;
if (!ciphertext && process.env.DEEC_CIPHER_TEXT) {
  ciphertext = process.env.DEEC_CIPHER_TEXT;
  ciphertextSource = 'direct';
}
if (!ciphertext && process.env.DEEC_CIPHER_TEXT_FILE) {
  ciphertext = fs.readFileSync(process.env.DEEC_CIPHER_TEXT_FILE, 'utf8');
  ciphertextSource = 'file';
}
if (!plaintext && process.env.DEEC_PLAINTEXT) {
  plaintext = process.env.DEEC_PLAINTEXT;
  plaintextSource = 'direct';
}
if (!plaintext && process.env.DEEC_PLAINTEXT_FILE) {
  plaintext = fs.readFileSync(process.env.DEEC_PLAINTEXT_FILE, 'utf8');
  plaintextSource = 'file';
}

if (mode === 'decrypt' && !ciphertext) {
  printHelp();
  console.error('Error: No ciphertext provided for decryption.');
  process.exit(1);
}
if (mode === 'encrypt' && !plaintext) {
  printHelp();
  console.error('Error: No plaintext provided for encryption.');
  process.exit(1);
}

const rsa = new RSACrypto();
rsa.loadKeyDirectory(keyDir);

if (mode === 'decrypt') {
  try {
    const { keyId, data, padding, hash } = rsa.decrypt(ciphertext);
    const outputObj = {
      keyId,
      padding,
      hash: hash || null,
      output: data.toString('utf8')
    };
    if (outputPath) {
      const out = outputRaw ? data.toString('utf8') : JSON.stringify(outputObj, null, 2);
      fs.writeFileSync(outputPath, out);
    } else {
      if (outputRaw) {
        console.log(data.toString('utf8'));
      } else {
        try {
          console.log(JSON.stringify(outputObj, null, 2));
        } catch {
          console.log(data.toString('utf8'));
        }
      }
    }
  } catch (err) {
    console.error('Decryption failed:', err.message);
    process.exit(1);
  }
}

if (mode === 'encrypt') {
  const keys = Object.keys(rsa.publicKeys);
  if (keys.length === 0) {
    console.error('No public keys found in', keyDir);
    process.exit(1);
  }

  const selectedKey = keyId && rsa.publicKeys[keyId]
    ? keyId
    : keyId
      ? (console.error(`Key ID '${keyId}' not found in key directory.`), process.exit(1))
      : keys[0];

  try {
    const encrypted = rsa.encrypt(plaintext, selectedKey, useAES);
    const output = encrypted.toString('base64');
    if (outputPath) {
      fs.writeFileSync(outputPath, output);
    } else {
      console.log(output);
    }
  } catch (err) {
    console.error('Encryption failed:', err.message);
    process.exit(1);
  }
}

