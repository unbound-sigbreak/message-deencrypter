const fs = require('fs');
const path = require('path');
const {
  publicEncrypt,
  privateDecrypt,
  constants
} = require('crypto');

class RSACrypto {
  constructor() {
    this.publicKeys = {};
    this.privateKeys = {};
  }

  loadKeyDirectory(dirPath) {
    const files = fs.readdirSync(dirPath);
    for (const file of files) {
      const match = file.match(/^(.+?)\.(pub|priv)\.pem$/);
      if (!match) continue;

      const [, keyId, type] = match;
      const fullPath = path.join(dirPath, file);
      const pem = fs.readFileSync(fullPath, 'utf8');

      if (type === 'pub') this.publicKeys[keyId] = pem;
      else if (type === 'priv') this.privateKeys[keyId] = pem;
    }
  }

  encrypt(data, keyId) {
    const pubKey = this.publicKeys[keyId];
    if (!pubKey) throw new Error(`Public key "${keyId}" not found`);
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    return publicEncrypt(
      {
        key: pubKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      buffer
    );
  }

  decrypt(input, forcedKeyId = null) {
    const buffer = Buffer.isBuffer(input) ? input : this._tryDecode(input);

    const keysToTry = forcedKeyId
      ? [[forcedKeyId, this.privateKeys[forcedKeyId]]]
      : Object.entries(this.privateKeys);

    for (const [keyId, privKey] of keysToTry) {
      if (!privKey) continue;
      for (const opts of this._getDecryptOptions(privKey)) {
        try {
          const result = privateDecrypt(opts, buffer);
          return {
            keyId,
            padding: opts.padding,
            hash: opts.oaepHash || null,
            data: result
          };
        } catch (_) {
          // Try next
        }
      }
    }

    throw new Error('Decryption failed with all known keys and paddings');
  }

  _tryDecode(input) {
    const trimmed = input.trim().replace(/\r?\n|\s+/g, '');

    // Try valid hex first (even length, only hex chars)
    if (/^[a-fA-F0-9]+$/.test(trimmed) && trimmed.length % 2 === 0) {
      try {
        return Buffer.from(trimmed, 'hex');
      } catch (_) { }
    }

    // Try base64 fallback
    if (/^[a-zA-Z0-9+/=]+$/.test(trimmed)) {
      try {
        return Buffer.from(trimmed, 'base64');
      } catch (_) { }
    }

    throw new Error('Unsupported encoding. Input must be valid base64 or hex.');
  }

  _getDecryptOptions(privKey) {
    return [
      // PKCS#1 v1.5
      {
        key: privKey,
        padding: constants.RSA_PKCS1_PADDING
      },
      // OAEP with all known supported digests
      {
        key: privKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha1'
      },
      {
        key: privKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha224'
      },
      {
        key: privKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      {
        key: privKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha384'
      },
      {
        key: privKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha512'
      }
    ];
  }
}

module.exports = RSACrypto;
