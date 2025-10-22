document.addEventListener('DOMContentLoaded', async () => {
  const pubkeyArea = document.getElementById('pubkey');
  const plaintextArea = document.getElementById('plaintext');
  const ciphertextArea = document.getElementById('ciphertext');
  const decryptedArea = document.getElementById('decrypted');
  const genKeyBtn = document.getElementById('genKeyBtn');
  const encryptBtn = document.getElementById('encryptBtn');
  const decryptBtn = document.getElementById('decryptBtn');
  const showMyPubBtn = document.getElementById('showMyPubBtn');
  const showMyPrivBtn = document.getElementById('showMyPrivBtn');
  const myPubkeyContainer = document.getElementById('myPubkeyContainer');
  const myPrivkeyContainer = document.getElementById('myPrivkeyContainer');
  const myPubkeyArea = document.getElementById('myPubkey');
  const myPrivkeyArea = document.getElementById('myPrivkey');
  const privWarning = document.getElementById('privWarning');
  const tooLongWarning = document.getElementById('tooLongWarning');
  const showHelpBtn = document.getElementById('showHelpBtn');
  const helpContainer = document.getElementById('helpContainer');

  const LOCAL_KEYPAIR = 'rsa-keypair';

  const importKey = async (pem, isPrivate) => {
    const type = isPrivate ? 'pkcs8' : 'spki';
    return await window.crypto.subtle.importKey(
      type,
      pemToArrayBuffer(pem),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      isPrivate ? ['decrypt'] : ['encrypt']
    );
  };

  const stripSpacesAndNewlines = (str) => str.replace(/[\s\r\n]+/g, '');

  const pemToArrayBuffer = (pem) => {
    const cleaned = pem.trim();

    if (cleaned.startsWith('ssh-rsa ') || cleaned.startsWith('ssh-ed25519 ')) {
      throw new Error('Unsupported key format: OpenSSH. Provide PEM SPKI with BEGIN PUBLIC KEY.');
    }
    if (cleaned.includes('BEGIN RSA PUBLIC KEY')) {
      throw new Error('Unsupported key format: PKCS#1. Convert to SPKI (BEGIN PUBLIC KEY).');
    }

    const noHeaders = cleaned
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s+/g, '');

    const bin = atob(noHeaders);
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
    } catch (err) {
      console.log('loadKeypair(): Failed to load keypair JSON', json, err);
      return null;
    }
  };

  const generateOnLoadIfEmpty = async () => {
    const existing = loadKeypair();
    if (existing) {
      return;
    }
    const { pubPem, privPem } = await generateKeypair();
    if (myPubkeyContainer.style.display === 'block') myPubkeyArea.value = pubPem;
    if (myPrivkeyContainer.style.display === 'block') myPrivkeyArea.value = privPem;
    return;
  };

  const confirmAndGenerate = async () => {
    const existing = loadKeypair();
    if (existing) {
      const ok = confirm(
        "A keypair already exists. Are you sure you want to overwrite it?\n\nYou will need to redistribute your public key, and will not be able to unencrypt previous messages, unless you've backed up your private key"
      );
      if (!ok) return;
    }
    const { pubPem, privPem } = await generateKeypair();
    if (myPubkeyContainer.style.display === 'block') myPubkeyArea.value = pubPem;
    if (myPrivkeyContainer.style.display === 'block') myPrivkeyArea.value = privPem;
  };

  const toggleHelp = () => {
    helpContainer.style.display = helpContainer.style.display === 'block' ? 'none' : 'block';
  };

  const toggleMyPublicKey = () => {
    const keys = loadKeypair();
    if (!keys) return alert('No keypair available.');
    myPubkeyArea.value = keys.pubPem;
    myPubkeyContainer.style.display = myPubkeyContainer.style.display === 'block' ? 'none' : 'block';
  };

  const toggleMyPrivateKey = () => {
    const keys = loadKeypair();
    if (!keys) return alert('No keypair available.');
    myPrivkeyArea.value = keys.privPem;
    const showing = myPrivkeyContainer.style.display === 'block';
    myPrivkeyContainer.style.display = showing ? 'none' : 'block';
    privWarning.style.display = showing ? 'none' : 'block';
  };

  const encryptMessage = async () => {
    const recipientPem = document.getElementById('pubkey').value.trim();
    if (!recipientPem) {
      alert("Paste a recipient's public key first.");
      return;
    }

    let publicKey;
    try {
      publicKey = await window.crypto.subtle.importKey(
        'spki',
        pemToArrayBuffer(recipientPem),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['encrypt']
      );
    } catch (e) {
      alert(
        'Failed to import public key. Use SPKI PEM:\n' +
        '-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----\n' +
        'If you have PKCS#1 (BEGIN RSA PUBLIC KEY), convert:\n' +
        '  openssl rsa -RSAPublicKey_in -in pkcs1.pub -pubout -out spki.pub'
      );
      return;
    }

    const encoded = new TextEncoder().encode(document.getElementById('plaintext').value);
    const MAX_LEN = 190;
    if (encoded.length > MAX_LEN) {
      alert(`Message too long for RSA-OAEP-256 (max ${MAX_LEN} bytes).`);
      return;
    }

    const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, encoded);
    document.getElementById('ciphertext').value = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
  };

  const checkInputLength = () => {
    const len = new TextEncoder().encode(plaintextArea.value).length;
    if (len > 190) {
      tooLongWarning.textContent = `Message is too long (${len} bytes). Keep it < 190 bytes.`;
      tooLongWarning.style.display = 'block';
    } else {
      tooLongWarning.style.display = 'none';
    }
  };

  const decryptMessage = async () => {
    const keys = loadKeypair();
    if (!keys) return alert('Keypair not loaded.');
    const privateKey = await importKey(keys.privPem, true);
    try {
      const raw = atob(stripSpacesAndNewlines(ciphertextArea.value));
      const buf = new Uint8Array([...raw].map(c => c.charCodeAt(0)));
      const decrypted = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, buf);
      decryptedArea.value = new TextDecoder().decode(decrypted);
    } catch {
      decryptedArea.value = '[Decryption failed]';
    }
  };
  
  const selectAllOnFocus = (element) => {
    const handler = () => {
      element?.select();
      element?.setSelectionRange?.(0, element.value.length);
    };
    element.addEventListener('focus', handler);
    element.addEventListener('click', handler);
    element.addEventListener('mouseup', (e) => e.preventDefault());
  };

  await generateOnLoadIfEmpty();
  const keys = loadKeypair();
  if (keys?.pubPem && !pubkeyArea.value) pubkeyArea.value = '';

  selectAllOnFocus(myPubkeyArea);
  selectAllOnFocus(ciphertextArea);

  genKeyBtn.onclick = confirmAndGenerate;
  showHelpBtn.onclick = toggleHelp;
  showMyPubBtn.onclick = toggleMyPublicKey;
  showMyPrivBtn.onclick = toggleMyPrivateKey;
  encryptBtn.onclick = encryptMessage;
  decryptBtn.onclick = decryptMessage;
  plaintextArea.onchange = checkInputLength;
  plaintextArea.oninput = checkInputLength;
});
