document.addEventListener('DOMContentLoaded', () => {
  const pubkeyArea = document.getElementById('pubkey');
  const plaintextArea = document.getElementById('plaintext');
  const ciphertextArea = document.getElementById('ciphertext');
  const decryptedArea = document.getElementById('decrypted');
  const genKeyBtn = document.getElementById('genKeyBtn');
  const exportPrivBtn = document.getElementById('exportPrivBtn');
  const encryptBtn = document.getElementById('encryptBtn');
  const decryptBtn = document.getElementById('decryptBtn');

  const LOCAL_KEYPAIR = 'rsa-keypair';

  const importKey = async (pem, isPrivate) => {
    const type = isPrivate ? 'pkcs8' : 'spki';
    return await window.crypto.subtle.importKey(
      'pkcs8' === type ? 'pkcs8' : 'spki',
      pemToArrayBuffer(pem),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      isPrivate ? ['decrypt'] : ['encrypt']
    );
  };

  const pemToArrayBuffer = (pem) => {
    const b64 = pem.replace(/-----(BEGIN|END)[^\\n]+-----/g, '').replace(/\\s+/g, '');
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  };

  const arrayBufferToPem = (buffer, type) => {
    const b64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    const lines = b64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----`;
  };

  const generateKeypair = async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['encrypt', 'decrypt']
    );
    const pub = await crypto.subtle.exportKey('spki', key.publicKey);
    const priv = await crypto.subtle.exportKey('pkcs8', key.privateKey);
    const pubPem = arrayBufferToPem(pub, 'PUBLIC KEY');
    const privPem = arrayBufferToPem(priv, 'PRIVATE KEY');
    localStorage.setItem(LOCAL_KEYPAIR, JSON.stringify({ pubPem, privPem }));
    return { pubPem, privPem };
  };

  const loadKeypair = () => {
    const json = localStorage.getItem(LOCAL_KEYPAIR);
    if (!json) return null;
    try {
      return JSON.parse(json);
    } catch {
      return null;
    }
  };

  const confirmAndGenerate = async () => {
    const existing = loadKeypair();
    if (existing) {
      const ok = confirm('A keypair already exists. Are you sure you want to overwrite it?');
      if (!ok) return;
    }
    const { pubPem } = await generateKeypair();
    pubkeyArea.value = pubPem;
  };

  const showPrivateKey = () => {
    const keys = loadKeypair();
    if (keys) alert(keys.privPem);
    else alert('No keypair available.');
  };

  const encryptMessage = async () => {
    const keys = loadKeypair();
    if (!keys) return alert('Keypair not loaded.');
    const publicKey = await importKey(keys.pubPem, false);
    const encoded = new TextEncoder().encode(plaintextArea.value);

    const MAX_LEN = 190;
    if (encoded.length > MAX_LEN) {
      return alert(`Message too long for RSA-OAEP-256 (max ${MAX_LEN} bytes).`);
    }

    const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, encoded);
    ciphertextArea.value = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
  };

  const decryptMessage = async () => {
    const keys = loadKeypair();
    if (!keys) return alert('Keypair not loaded.');
    const privateKey = await importKey(keys.privPem, true);
    try {
      const raw = atob(ciphertextArea.value);
      const buf = new Uint8Array([...raw].map(c => c.charCodeAt(0)));
      const decrypted = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, buf);
      decryptedArea.value = new TextDecoder().decode(decrypted);
    } catch (e) {
      decryptedArea.value = '[Decryption failed]';
    }
  };

  // Init
  const keys = loadKeypair();
  if (keys?.pubPem) pubkeyArea.value = keys.pubPem;

  genKeyBtn.onclick = confirmAndGenerate;
  exportPrivBtn.onclick = showPrivateKey;
  encryptBtn.onclick = encryptMessage;
  decryptBtn.onclick = decryptMessage;
});
