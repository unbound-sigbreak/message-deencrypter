const fs = require('fs');
const path = require('path');
const {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  publicEncrypt,
  privateDecrypt,
  constants
} = require('crypto');


class RSACrypto {
  constructor() {
    this.publicKeys = {};
    this.privateKeys = {};
  }

  _encryptHybridAES(data, pubKeyPem) {
    const aesKey = randomBytes(32); // AES-256
    const iv = randomBytes(12); // For AES-GCM
    const cipher = createCipheriv('aes-256-gcm', aesKey, iv);

    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    const tag = cipher.getAuthTag();

    const rsaEncryptedKey = publicEncrypt(
      {
        key: pubKeyPem,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      aesKey
    );

    return Buffer.from(
      JSON.stringify({
        type: 'hybrid',
        alg: 'RSA-OAEP-256+AES-256-GCM',
        key: rsaEncryptedKey.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        ct: encrypted.toString('base64')
      })
    );
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

  encrypt(data, keyId, useAES = false) {
    const pubKey = this.publicKeys[keyId];
    if (!pubKey) throw new Error(`Public key "${keyId}" not found`);

    if (useAES) {
      return this._encryptHybridAES(data, pubKey);
    }

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

    let parsed;
    try {
      parsed = JSON.parse(buffer.toString('utf8'));
    } catch (_) {
      parsed = null;
    }

    if (parsed?.type === 'hybrid' && parsed.key && parsed.iv && parsed.ct) {
      const rsaKeys = forcedKeyId
        ? [[forcedKeyId, this.privateKeys[forcedKeyId]]]
        : Object.entries(this.privateKeys);

      for (const [keyId, privKey] of rsaKeys) {
        if (!privKey) continue;

        for (const opts of this._getDecryptOptions(privKey)) {
          try {
            const decryptedKey = privateDecrypt(
              { key: privKey, ...opts },
              Buffer.from(parsed.key, 'base64')
            );

            const decipher = createDecipheriv(
              'aes-256-gcm',
              decryptedKey,
              Buffer.from(parsed.iv, 'base64')
            );

            decipher.setAuthTag(Buffer.from(parsed.tag, 'base64'));
            const decrypted = Buffer.concat([
              decipher.update(Buffer.from(parsed.ct, 'base64')),
              decipher.final()
            ]);

            return {
              keyId,
              padding: opts.padding,
              hash: opts.oaepHash || null,
              data: decrypted
            };
          } catch (_) {
            // try next
          }
        }
      }

      throw new Error('Hybrid AES decryption failed with all known keys');
    }

    // Fallback to normal RSA decryption
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
