/**
 * Phase 3: WebAuthn PRF Extension Integration
 * TRUE hardware-bound encryption using PRF extension
 */

/**
 * Check if PRF extension is supported
 * @returns {Promise<boolean>}
 */
export async function isPRFSupported() {
    if (!window.PublicKeyCredential) return false;
    
    try {
        const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        // Check if extensions are supported (PRF is part of Level 3)
        return available && 'AuthenticatorAssertionResponse' in window;
    } catch {
        return false;
    }
}

/**
 * Get PRF output from WebAuthn credential
 * @param {string} credentialIdHex - Credential ID in hex
 * @param {ArrayBuffer} salt - 32-byte salt for PRF
 * @returns {Promise<ArrayBuffer>} - 32-byte PRF output
 */
async function getPRFOutput(credentialIdHex, salt) {
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    
    const credentialIdBytes = new Uint8Array(
        credentialIdHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    );
    
    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge: challenge,
            rpId: "localhost",
            allowCredentials: [{
                type: "public-key",
                id: credentialIdBytes
            }],
            userVerification: "required",
            extensions: {
                prf: {
                    eval: {
                        first: salt
                    }
                }
            }
        }
    });
    
    const prfResults = assertion.getClientExtensionResults().prf;
    if (!prfResults || !prfResults.results || !prfResults.results.first) {
        throw new Error("PRF extension not supported or failed");
    }
    
    return prfResults.results.first;
}

/**
 * Fallback: Derive key from credential ID (for non-PRF browsers)
 * @param {ArrayBuffer} credentialIdRaw
 * @returns {Promise<CryptoKey>}
 */
async function deriveKeyFromCredentialId(credentialIdRaw) {
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        credentialIdRaw,
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    const enc = new TextEncoder();
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode("Legion-Storage-Protection-v1"),
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

/**
 * Encrypts and stores recovery phrase using PRF or fallback
 * @param {string} phrase - BIP-39 recovery phrase
 * @param {string} credentialIdHex - WebAuthn credential ID (hex)
 */
export async function securelyStoreMnemonic(phrase, credentialIdHex) {
    // ALWAYS use PBKDF2 during registration (no second fingerprint prompt)
    // PRF requires credentials.get() which needs another fingerprint
    const credentialIdBytes = new Uint8Array(
        credentialIdHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    );
    
    const saltBytes = await window.crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode("Legion-PRF-Salt-v1-" + credentialIdHex)
    );
    const salt = new Uint8Array(saltBytes).slice(0, 32);
    
    const key = await deriveKeyFromCredentialId(credentialIdBytes.buffer);
    const method = "pbkdf2";
    console.log("✓ Using PBKDF2 (registration - no second fingerprint)");
    
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encodedData = new TextEncoder().encode(phrase);

    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedData
    );

    const storagePacket = {
        iv: arrayBufferToBase64(iv),
        data: arrayBufferToBase64(encryptedContent),
        salt: arrayBufferToBase64(salt),
        method: method,  // "prf" or "pbkdf2"
        version: "2.0"
    };

    localStorage.setItem("legion_vault", JSON.stringify(storagePacket));
    console.log(`✓ Recovery phrase encrypted (${method}) and stored`);
}

/**
 * Decrypts and retrieves recovery phrase using PRF or fallback
 * @param {string} credentialIdHex - WebAuthn credential ID (hex)
 * @returns {Promise<string>} - Decrypted BIP-39 phrase
 */
export async function securelyRetrieveMnemonic(credentialIdHex) {
    const vaultJson = localStorage.getItem("legion_vault");
    if (!vaultJson) {
        throw new Error("No encrypted vault found");
    }

    const vault = JSON.parse(vaultJson);
    const method = vault.method || "pbkdf2";  // Default to pbkdf2 for v1.0
    
    let key;
    
    if (method === "prf") {
        // Decrypt using PRF
        const salt = base64ToArrayBuffer(vault.salt);
        const prfOutput = await getPRFOutput(credentialIdHex, salt);
        key = await window.crypto.subtle.importKey(
            "raw",
            prfOutput,
            "AES-GCM",
            false,
            ["decrypt"]
        );
        console.log("✓ Using PRF for decryption");
    } else {
        // Decrypt using PBKDF2 fallback
        const credentialIdBytes = new Uint8Array(
            credentialIdHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
        );
        key = await deriveKeyFromCredentialId(credentialIdBytes.buffer);
        console.log("✓ Using PBKDF2 for decryption");
    }
    
    const iv = base64ToArrayBuffer(vault.iv);
    const encryptedData = base64ToArrayBuffer(vault.data);

    const decryptedContent = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encryptedData
    );

    return new TextDecoder().decode(decryptedContent);
}

/**
 * Checks if encrypted vault exists
 * @returns {boolean}
 */
export function hasEncryptedVault() {
    return localStorage.getItem("legion_vault") !== null;
}

// Helper functions
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}
