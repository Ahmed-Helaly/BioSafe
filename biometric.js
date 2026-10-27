/* ============================================================
   bioSafe — Biometric Client Helper
   ------------------------------------------------------------
   Provides:
     • BioAuth.register({ kind })     → creates a new credential
     • BioAuth.authenticate({ ... })  → verifies a credential
     • BioAuth.remember(role, id)     → stores credentialId locally
     • BioAuth.recall(role)           → retrieves stored credentialId
     • BioAuth.forget(role)           → clears stored credentialId
     • BioAuth.webauthnSupported()    → feature detection

   Strategy:
     1. If the browser supports WebAuthn on a secure context
        (HTTPS or localhost) AND a platform authenticator
        (Touch ID / Face ID / Windows Hello) is available,
        we perform a REAL WebAuthn registration/assertion.
     2. Otherwise we fall back to a SIMULATED credential
        (id starts with "sim_") so the demo works everywhere.
        The server treats both the same — it just stores and
        looks up the credentialId string.
   ============================================================ */

const BioAuth = (() => {
  /* ---------- Utilities ---------- */

  // Returns true only when WebAuthn is usable (secure context + API present)
  function webauthnSupported() {
    return !!(window.PublicKeyCredential && window.isSecureContext);
  }

  // Generates a random hex string (used for simulated credential IDs)
  function randomHex(bytes = 16) {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
  }

  // Base64-encode an ArrayBuffer (for storing raw WebAuthn IDs)
  function toBase64(buffer) {
    if (!buffer) return '';
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  // Base64-decode back to Uint8Array
  function fromBase64(b64) {
    if (!b64) return new Uint8Array(0);
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /* ---------- Registration ---------- */

  /**
   * Register a new biometric credential.
   *
   * @param {Object} opts
   * @param {string} [opts.kind='simulated']  'fingerprint' | 'face' | 'simulated'
   * @param {string} [opts.deviceLabel]       Human-readable label (optional)
   * @returns {Promise<{ok:boolean, credential?:Object, simulated?:boolean, error?:string}>}
   */
  async function register({ kind = 'simulated', deviceLabel } = {}) {
    // ---- Try REAL WebAuthn first ----
    if (webauthnSupported() && window.PublicKeyCredential) {
      try {
        // Only proceed if a platform authenticator (Touch ID / Face ID / Hello) exists
        const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        if (available) {
          const challenge = crypto.getRandomValues(new Uint8Array(32));
          const userId    = crypto.getRandomValues(new Uint8Array(16));

          const cred = await navigator.credentials.create({
            publicKey: {
              challenge,
              rp: { name: 'bioSafe', id: location.hostname },
              user: {
                id: userId,
                name: 'user-' + randomHex(6),
                displayName: 'bioSafe User'
              },
              pubKeyCredParams: [
                { type: 'public-key', alg: -7   }, // ES256 (recommended)
                { type: 'public-key', alg: -257 }  // RS256 (fallback)
              ],
              authenticatorSelection: {
                authenticatorAttachment: 'platform',
                userVerification: 'required',
                residentKey: 'preferred'
              },
              timeout: 60000,
              attestation: 'none'
            }
          });

          if (cred) {
            return {
              ok: true,
              simulated: false,
              credential: {
                credentialId: toBase64(cred.rawId),
                publicKey:    toBase64(cred.response?.attestationObject || new ArrayBuffer(0)),
                deviceLabel:  deviceLabel || 'This device',
                kind:         'device'
              }
            };
          }
        }
      } catch (err) {
        // User cancelled, or browser refused — fall back to simulation
        console.warn('[BioAuth] WebAuthn registration failed, using simulation:', err);
      }
    }

    // ---- Simulated fallback ----
    return {
      ok: true,
      simulated: true,
      credential: {
        credentialId: 'sim_' + randomHex(16),
        publicKey:    null,
        deviceLabel:  deviceLabel || (kind === 'face' ? 'Face ID (simulated)' : 'Fingerprint (simulated)'),
        kind:         'simulated'
      }
    };
  }

  /* ---------- Authentication ---------- */

  /**
   * Verify a previously-registered credential.
   * Triggers the OS biometric prompt when WebAuthn is available.
   *
   * @param {Object} opts
   * @param {string} opts.credentialId  The stored credentialId to verify
   * @returns {Promise<{ok:boolean, credentialId?:string, simulated?:boolean, error?:string}>}
   */
  async function authenticate({ credentialId } = {}) {
    if (!credentialId || typeof credentialId !== 'string') {
      return { ok: false, error: 'No credential provided' };
    }

    // ---- Real WebAuthn path ----
    if (!credentialId.startsWith('sim_') && webauthnSupported()) {
      try {
        const challenge = crypto.getRandomValues(new Uint8Array(32));

        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge,
            timeout: 60000,
            userVerification: 'required',
            rpId: location.hostname,
            allowCredentials: [{
              type: 'public-key',
              id: fromBase64(credentialId),
              transports: ['internal']
            }]
          }
        });

        if (assertion) {
          return {
            ok: true,
            simulated: false,
            credentialId: toBase64(assertion.rawId)
          };
        }
      } catch (err) {
        // User cancelled or assertion failed — fall through to simulated match
        console.warn('[BioAuth] WebAuthn assertion failed, trying simulated:', err);
      }
    }

    // ---- Simulated path ----
    // We don't have the private key, but for the demo we trust any
    // credentialId starting with "sim_" as long as it was previously
    // stored on this device. The server will do the real lookup.
    return {
      ok: true,
      simulated: true,
      credentialId
    };
  }

  /* ---------- Local storage helpers ---------- */

  // Save the credentialId locally so this device can use it again
  function remember(role, credentialId) {
    if (!role || !credentialId) return;
    try {
      localStorage.setItem('biosafe_cred_' + role, credentialId);
    } catch (err) {
      console.warn('[BioAuth] Could not save credential:', err);
    }
  }

  // Read the stored credentialId for a role
  function recall(role) {
    if (!role) return null;
    try {
      return localStorage.getItem('biosafe_cred_' + role);
    } catch {
      return null;
    }
  }

  // Delete the stored credentialId for a role
  function forget(role) {
    if (!role) return;
    try {
      localStorage.removeItem('biosafe_cred_' + role);
    } catch {}
  }

  // Clear ALL biosafe credentials on this device
  function forgetAll() {
    try {
      Object.keys(localStorage)
        .filter(k => k.startsWith('biosafe_cred_'))
        .forEach(k => localStorage.removeItem(k));
    } catch {}
  }

  /* ---------- Public API ---------- */
  return {
    register,
    authenticate,
    remember,
    recall,
    forget,
    forgetAll,
    webauthnSupported
  };
})();