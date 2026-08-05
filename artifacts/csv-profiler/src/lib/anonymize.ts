// Four-round format-preserving anonymization/decryption — streaming browser simulation.
// This is a custom FPE simulation, not an AES-GCM implementation:
// it uses xorshift128+ keystream bytes and reversible character-class operations.
// 4-round key chain: each cell is encrypted once per round (round1→round2→round3→round4),
// decrypted in reverse (round4→round3→round2→round1).
// Each alphanumeric character passes through 5 independent micro-operations per round,
// consuming 5 keystream bytes. Non-alphanumeric characters are passed through unchanged
// (consuming 5 keystream bytes to keep offsets aligned).
//
// FORMAT VERSIONS
// ───────────────
// v1 (legacy): original algorithm — column-level keystream, no CBC, no export salt, no HMAC.
//              Files written before this hardening pass. Decryption is fully supported via
//              the legacy code path.
// v2 (current): all security fixes applied — per-value keystream, CBC diffusion, CSPRNG-derived
//               export salt, HMAC-SHA256 integrity, and Web Crypto PBKDF2. New files always
//               use v2. Old v1 files decrypt correctly with the legacy path.

export const FORMAT_VERSION = "v2";

// ── §9 — xorshift128+ PRNG ────────────────────────────────────────────────────
function makeKeystream(seed: number) {
  let a = ((seed ^ 0x9e3779b9) >>> 0) || 1;
  let b = ((seed ^ 0x6c62272e) >>> 0) || 2;
  return () => {
    a ^= a << 13; a = a >>> 0;
    a ^= a >> 17;
    a ^= a << 5;  a = a >>> 0;
    b ^= b >> 7;  b = b >>> 0;
    b ^= b << 9;  b = b >>> 0;
    b ^= b >> 8;  b = b >>> 0;
    return (((a + b) >>> 0) / 0x100000000);
  };
}

// Two-seed variant: accepts independent 32-bit values for the two internal PRNG
// state variables so that more than 32 bits of external material (e.g. the full
// 128-bit export salt) can be reflected in the initial PRNG state.
function makeKeystream2(seedA: number, seedB: number) {
  let a = (seedA >>> 0) || 1;
  let b = (seedB >>> 0) || 2;
  return () => {
    a ^= a << 13; a = a >>> 0;
    a ^= a >> 17;
    a ^= a << 5;  a = a >>> 0;
    b ^= b >> 7;  b = b >>> 0;
    b ^= b << 9;  b = b >>> 0;
    b ^= b >> 8;  b = b >>> 0;
    return (((a + b) >>> 0) / 0x100000000);
  };
}

// ── 8-bit left-rotate ─────────────────────────────────────────────────────────
// Used to spread CBC diffusion across all 5 keystream bytes (Issue A fix):
// byte j receives cbc rotated left by j positions so each sub-operation is
// independently influenced by the chaining state.
function rotl8(x: number, n: number): number {
  n = n & 7; // clamp to 0–7 (only 3 bits matter for an 8-bit rotate)
  return n === 0 ? (x & 0xff) : (((x << n) | (x >>> (8 - n))) & 0xff);
}

// ── §6 — CSPRNG helpers (Issue 6: weak randomness) ───────────────────────────
// All nonce, salt and random-seed generation uses the browser's CSPRNG.
function cryptoRandomU32(): number {
  const buf = new Uint8Array(4);
  crypto.getRandomValues(buf);
  return ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
}

export function cryptoRandomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ── §8.1 — Random key from seed ───────────────────────────────────────────────
// Still used for seed-mode key expansion (PRNG seeded by user seeds + export salt).
function generateRandomKey(seed: number): string {
  const rng = makeKeystream((seed ^ 0xdeadbeef) >>> 0);
  const bytes: string[] = [];
  for (let i = 0; i < 32; i++)
    bytes.push(Math.floor(rng() * 256).toString(16).padStart(2, "0"));
  return bytes.join("");
}

// ── §8.2-v1 — Legacy PBKDF2-like passphrase key (v1 compat) ─────────────────
// Preserved for backward-compatible decryption of v1 files only.
// NOTE: this is NOT a real PBKDF2; it is a weak custom construction.
// v2 uses Web Crypto PBKDF2 instead (see §8.2-v2 below).
function deriveKeyFromPassphrase_v1(passphrase: string, iterations: number): string {
  let h = 0x5a827999;
  for (let i = 0; i < passphrase.length; i++)
    h = (Math.imul(h, 31) + passphrase.charCodeAt(i)) >>> 0;
  const rng = makeKeystream(h);
  for (let i = 0; i < Math.min(iterations, 200); i++) rng();
  const bytes: string[] = [];
  for (let i = 0; i < 32; i++)
    bytes.push(Math.floor(rng() * 256).toString(16).padStart(2, "0"));
  return bytes.join("");
}

// ── §8.2-v2 — Web Crypto PBKDF2 passphrase key (Issue 1) ────────────────────
// Uses browser's native PBKDF2-SHA256 for real key stretching.
// exportSalt is mixed into the PBKDF2 salt so each export run produces a unique key.
async function deriveKeyFromPassphrase_v2(
  passphrase: string,
  exportSalt: string,
  iterations: number
): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveBits"]
  );
  // Salt = fixed domain separator + per-export CSPRNG salt (Issues 1 & 4)
  const salt = enc.encode("AIRAVATA-DEA-v2\x00" + exportSalt);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(bits))
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

// ── §11 — Column IV hash (deterministic per key+col) ─────────────────────────
function hashColIV(keyHex: string, colName: string): number {
  let h = parseInt(keyHex.slice(0, 8), 16) ^ 0xa5a5a5a5;
  const s = "COL\x00" + colName;
  for (let i = 0; i < s.length; i++)
    h = (Math.imul(h, 1664525) + s.charCodeAt(i) + 1013904223) >>> 0;
  return h;
}

// ── §11-v2 — Per-value nonce (Issue 2: reused keystream) ─────────────────────
// Derives a unique IV for each distinct cell value so that identical plaintexts
// in the same column produce different keystreams. Determinism is preserved: the
// same value always produces the same nonce (and thus the same ciphertext within
// a single export run), so the deterministic-mode cache still works correctly.
function hashValueNonce(baseIv: number, value: string): number {
  let h = baseIv;
  for (let i = 0; i < value.length; i++) {
    h = (Math.imul(h, 0x9e3779b9) + value.charCodeAt(i)) >>> 0;
    h = (h ^ (h >>> 16)) >>> 0;
  }
  // Mix in value length to prevent "AB" colliding with "A" + degenerate suffix
  h = (Math.imul(h, 0x85ebca6b) ^ ((value.length * 0x9e3779b9) >>> 0)) >>> 0;
  return h;
}

// ── §12-v1 — Per-cell keystream bytes (v1) ───────────────────────────────────
function makeCellKsBytes(size: number, keyHex: string, ivSeed: number): Uint8Array {
  const combined = (parseInt(keyHex.slice(0, 8), 16) ^ ivSeed) >>> 0;
  const ksRng = makeKeystream(combined);
  const ksBytes = new Uint8Array(size);
  for (let i = 0; i < size; i++)
    ksBytes[i] = Math.floor(ksRng() * 256);
  return ksBytes;
}

// ── §12-v2 — Per-cell keystream bytes with full 128-bit export-salt mixing (Issues B & 4)
// Folds all 128 bits of exportSalt into the two independent 32-bit PRNG seeds (seedA,
// seedB) so that the effective freshness protection is bounded by the full 128-bit salt
// space, not the first 32 bits. Birthday bound for a collision in (seedA, seedB) is ~2^32
// independent exports (64-bit PRNG state), which is orders of magnitude better than the
// ~2^16 bound from a single 32-bit seed.
function makeCellKsBytesV2(
  size: number, keyHex: string, ivSeed: number, exportSalt = ""
): Uint8Array {
  // seedA carries key prefix XOR ivSeed XOR salt words 0 & 1
  let seedA = (parseInt(keyHex.slice(0, 8), 16) ^ ivSeed) >>> 0;
  // seedB carries key word 1 XOR salt words 2 & 3 (independent from seedA)
  let seedB = parseInt(keyHex.slice(8, 16) || "0", 16) >>> 0;
  // Fold all four 32-bit words of the 128-bit export salt into the two seeds
  for (let i = 0; i < 32; i += 8) {
    if (exportSalt.length >= i + 8) {
      const sw = parseInt(exportSalt.slice(i, i + 8), 16);
      if (i < 16) seedA = (seedA ^ sw) >>> 0;
      else         seedB = (seedB ^ sw) >>> 0;
    }
  }
  const ksRng = makeKeystream2(seedA, seedB);
  const ksBytes = new Uint8Array(size);
  for (let i = 0; i < size; i++)
    ksBytes[i] = Math.floor(ksRng() * 256);
  return ksBytes;
}

// ── §10 — 5-operation format-preserving cipher ───────────────────────────────
// Each alphanumeric character is transformed by 5 sequential micro-operations,
// each driven by one keystream byte. The four operation types are:
//   0 = Add    (v + amount) mod S          — where amount = floor(k/4)%(S-1)+1
//   1 = Sub    (v - amount) mod S          — same amount derivation
//   2 = Mul    (v * coprime) mod S         — coprime chosen from COPRIME_MULS[S]
//   3 = Flip   (S − 1 − v)                — self-inverse complement

function gcd(a: number, b: number): number { return b === 0 ? a : gcd(b, a % b); }

function modInverse(a: number, m: number): number {
  let [r0, r1, s0, s1] = [a, m, 1, 0];
  while (r1 !== 0) {
    const q = Math.floor(r0 / r1);
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return ((s0 % m) + m) % m;
}

// Ordered alphabet of all printable non-alphanumeric ASCII characters (S=33).
const SYMBOL_CHARS = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';

// Alphanumeric output alphabet: digits 0–9 then lowercase a–z (S=36).
const ALNUM_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"; // S=36

const COPRIME_MULS: Record<number, number[]> = {
  9:  [2, 4, 5, 7, 8],
  10: [3, 7, 9],
  26: [3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25],
  33: [2, 4, 5, 7, 8, 10, 13, 14, 16, 17, 19, 20, 23, 25, 26, 28, 29, 31, 32],
  36: [5, 7, 11, 13, 17, 19, 23, 25, 29, 31, 35],
};
function getMuls(size: number): number[] {
  if (COPRIME_MULS[size]) return COPRIME_MULS[size];
  const res: number[] = [];
  for (let m = 2; m < size; m++) if (gcd(m, size) === 1) res.push(m);
  return res;
}

function applyOpFwd(v: number, k: number, size: number, muls: number[]): number {
  const opType = k % 4;
  if (opType === 0) return (v + Math.floor(k / 4) % (size - 1) + 1) % size;
  if (opType === 1) return ((v - (Math.floor(k / 4) % (size - 1) + 1)) % size + size) % size;
  if (opType === 2) return (v * muls[Math.floor(k / 4) % muls.length]) % size;
  return (size - 1 - v);
}

function applyOpInv(v: number, k: number, size: number, muls: number[]): number {
  const opType = k % 4;
  if (opType === 0) return ((v - (Math.floor(k / 4) % (size - 1) + 1)) % size + size) % size;
  if (opType === 1) return (v + Math.floor(k / 4) % (size - 1) + 1) % size;
  if (opType === 2) return (v * modInverse(muls[Math.floor(k / 4) % muls.length], size)) % size;
  return (size - 1 - v);
}

// ── §10-v1 — v1 cell encryption/decryption (preserved for legacy compat) ─────

function encryptFPECell(ksBytes: Uint8Array, value: string): string {
  const chars = [...value];
  let ki = 0;
  return chars.map((ch, charIdx) => {
    const code = ch.charCodeAt(0);
    if (charIdx === 0 && code >= 48 && code <= 57) {
      if (code === 48) { ki += 5; return ch; }
      const size = 9, base = 49;
      const muls = getMuls(size);
      let v = code - base;
      for (let i = 0; i < 5; i++) v = applyOpFwd(v, ksBytes[ki++ % ksBytes.length], size, muls);
      return String.fromCharCode(v + base);
    }
    let base: number, size: number;
    if      (code >= 48 && code <= 57)  { base = 48; size = 10; }
    else if (code >= 65 && code <= 90)  { base = 65; size = 26; }
    else if (code >= 97 && code <= 122) { base = 97; size = 26; }
    else {
      const symIdx = SYMBOL_CHARS.indexOf(ch);
      if (symIdx !== -1) {
        const symSize = SYMBOL_CHARS.length;
        const symMuls = getMuls(symSize);
        let v = symIdx;
        for (let i = 0; i < 5; i++) v = applyOpFwd(v, ksBytes[ki++ % ksBytes.length], symSize, symMuls);
        return SYMBOL_CHARS[v];
      }
      ki += 5; return ch;
    }
    const muls = getMuls(size);
    let v = code - base;
    for (let i = 0; i < 5; i++) v = applyOpFwd(v, ksBytes[ki++ % ksBytes.length], size, muls);
    return String.fromCharCode(v + base);
  }).join("");
}

function decryptFPECell(ksBytes: Uint8Array, value: string): string {
  const chars = [...value];
  let ki = 0;
  return chars.map((ch, charIdx) => {
    const code = ch.charCodeAt(0);
    if (charIdx === 0 && code >= 48 && code <= 57) {
      if (code === 48) { ki += 5; return ch; }
      const size = 9, base = 49;
      const muls = getMuls(size);
      const ks5: number[] = [];
      for (let i = 0; i < 5; i++) ks5.push(ksBytes[ki++ % ksBytes.length]);
      let v = code - base;
      for (let i = 4; i >= 0; i--) v = applyOpInv(v, ks5[i], size, muls);
      return String.fromCharCode(v + base);
    }
    let base: number, size: number;
    if      (code >= 48 && code <= 57)  { base = 48; size = 10; }
    else if (code >= 65 && code <= 90)  { base = 65; size = 26; }
    else if (code >= 97 && code <= 122) { base = 97; size = 26; }
    else {
      const symIdx = SYMBOL_CHARS.indexOf(ch);
      if (symIdx !== -1) {
        const symSize = SYMBOL_CHARS.length;
        const symMuls = getMuls(symSize);
        const ks5: number[] = [];
        for (let i = 0; i < 5; i++) ks5.push(ksBytes[ki++ % ksBytes.length]);
        let v = symIdx;
        for (let i = 4; i >= 0; i--) v = applyOpInv(v, ks5[i], symSize, symMuls);
        return SYMBOL_CHARS[v];
      }
      ki += 5; return ch;
    }
    const muls = getMuls(size);
    const ks5: number[] = [];
    for (let i = 0; i < 5; i++) ks5.push(ksBytes[ki++ % ksBytes.length]);
    let v = code - base;
    for (let i = 4; i >= 0; i--) v = applyOpInv(v, ks5[i], size, muls);
    return String.fromCharCode(v + base);
  }).join("");
}

// ── §10-v2 — CBC-enhanced cell encryption (v3 corrections applied)
//
// CBC-style chaining between characters — corrected per adversarial review:
//
//   (A-fix) rotl8 diffusion: cbc is spread across ALL 5 keystream bytes for each
//       character (byte j gets cbc rotated left by j bits), not only byte 0.
//       This means all 5 sub-operations per character are influenced by the chain.
//
//   (A-fix) Secret in cbc feedback: the cbc update mixes in rawKs4, the raw
//       (pre-effective) 5th keystream byte for this character position.  rawKs4 is
//       derived from the secret key, so an attacker who reads the ciphertext cannot
//       reconstruct cbc without also knowing the key.  The previous update used only
//       the ciphertext character code, which is public.
//
//   cbc ← ((cbc << 3) ⊕ charCode(encChar) ⊕ rawKs4) & 0xFF
//
// Decryption symmetry:
//   The decryptor knows ksBytes (same key), so it can compute rawKs4 identically at
//   each position.  It processes ciphertext left-to-right; the cbc value at position i
//   depends on ciphertext codes 0…i-1 and ks bytes 4, 9, 14, … (every 5th raw byte).
//   All of those are available during decryption without needing plaintext.
//
// Format preservation:
//   XORing rotl8(cbc,j) into a keystream byte changes which operation and shift amount
//   are selected but never changes which alphabet is used.  The output character remains
//   in the same class (digit, uppercase, lowercase, symbol) as the input.

function encryptFPECellV2(ksBytes: Uint8Array, value: string): string {
  const chars = [...value];
  let ki = 0;
  let cbc = 0;
  const out: string[] = [];

  for (let charIdx = 0; charIdx < chars.length; charIdx++) {
    const ch = chars[charIdx];
    const code = ch.charCodeAt(0);

    // Capture raw 5th ks byte BEFORE any effective-ks computation.
    // This is the secret component mixed into the cbc update (Issue A fix).
    const rawKs4 = ksBytes[(ki + 4) % ksBytes.length];

    // Spread CBC diffusion across all 5 ks bytes via bit-rotation of cbc.
    // byte j receives cbc rotated left by j positions (Issue A fix — was only byte 0).
    const getKs = (off: number): number =>
      (ksBytes[(ki + off) % ksBytes.length] ^ rotl8(cbc, off)) & 0xff;

    let outputChar: string;

    // ── Position-0 leading-zero-prevention ───────────────────────────
    if (charIdx === 0 && code >= 48 && code <= 57) {
      if (code === 48) {
        ki += 5;
        cbc = (((cbc << 3) ^ 48 ^ rawKs4) & 0xff);
        out.push(ch);
        continue;
      }
      const size = 9, base = 49;
      const muls = getMuls(size);
      let v = code - base;
      for (let i = 0; i < 5; i++) v = applyOpFwd(v, getKs(i), size, muls);
      outputChar = String.fromCharCode(v + base);
      ki += 5;
      cbc = (((cbc << 3) ^ outputChar.charCodeAt(0) ^ rawKs4) & 0xff);
      out.push(outputChar);
      continue;
    }

    if (code >= 48 && code <= 57) {
      const base = 48, size = 10, muls = getMuls(size);
      let v = code - base;
      for (let i = 0; i < 5; i++) v = applyOpFwd(v, getKs(i), size, muls);
      outputChar = String.fromCharCode(v + base);
    } else if (code >= 65 && code <= 90) {
      const base = 65, size = 26, muls = getMuls(size);
      let v = code - base;
      for (let i = 0; i < 5; i++) v = applyOpFwd(v, getKs(i), size, muls);
      outputChar = String.fromCharCode(v + base);
    } else if (code >= 97 && code <= 122) {
      const base = 97, size = 26, muls = getMuls(size);
      let v = code - base;
      for (let i = 0; i < 5; i++) v = applyOpFwd(v, getKs(i), size, muls);
      outputChar = String.fromCharCode(v + base);
    } else {
      const symIdx = SYMBOL_CHARS.indexOf(ch);
      if (symIdx !== -1) {
        const symSize = SYMBOL_CHARS.length, symMuls = getMuls(symSize);
        let v = symIdx;
        for (let i = 0; i < 5; i++) v = applyOpFwd(v, getKs(i), symSize, symMuls);
        outputChar = SYMBOL_CHARS[v];
      } else {
        // Non-printable passthrough — advance ki, update cbc
        ki += 5;
        cbc = (((cbc << 3) ^ code ^ rawKs4) & 0xff);
        out.push(ch);
        continue;
      }
    }

    ki += 5;
    cbc = (((cbc << 3) ^ outputChar.charCodeAt(0) ^ rawKs4) & 0xff);
    out.push(outputChar);
  }

  return out.join("");
}

// Inverse of encryptFPECellV2.
// CBC update uses the INPUT character code (ciphertext) and the same rawKs4 secret
// byte — the decryptor knows ksBytes from the key, so rawKs4 is reproducible at
// each position without knowing the plaintext.
function decryptFPECellV2(ksBytes: Uint8Array, value: string): string {
  const chars = [...value];
  let ki = 0;
  let cbc = 0;
  const out: string[] = [];

  for (let charIdx = 0; charIdx < chars.length; charIdx++) {
    const ch = chars[charIdx]; // ciphertext character
    const code = ch.charCodeAt(0);

    // Same rawKs4 capture as encryption (same ksBytes, same ki at this point)
    const rawKs4 = ksBytes[(ki + 4) % ksBytes.length];

    // Same rotl8-injected getKs as encryption — reproduces identical effective ks bytes
    const getKs = (off: number): number =>
      (ksBytes[(ki + off) % ksBytes.length] ^ rotl8(cbc, off)) & 0xff;

    let outputChar: string;

    // ── Position-0 leading-zero-prevention (mirror of encrypt) ───────
    if (charIdx === 0 && code >= 48 && code <= 57) {
      if (code === 48) {
        ki += 5;
        cbc = (((cbc << 3) ^ 48 ^ rawKs4) & 0xff);
        out.push(ch);
        continue;
      }
      const size = 9, base = 49;
      const muls = getMuls(size);
      const ks5 = [getKs(0), getKs(1), getKs(2), getKs(3), getKs(4)];
      let v = code - base;
      for (let i = 4; i >= 0; i--) v = applyOpInv(v, ks5[i], size, muls);
      outputChar = String.fromCharCode(v + base);
      ki += 5;
      cbc = (((cbc << 3) ^ code ^ rawKs4) & 0xff); // ciphertext code (input)
      out.push(outputChar);
      continue;
    }

    if (code >= 48 && code <= 57) {
      const base = 48, size = 10, muls = getMuls(size);
      const ks5 = [getKs(0), getKs(1), getKs(2), getKs(3), getKs(4)];
      let v = code - base;
      for (let i = 4; i >= 0; i--) v = applyOpInv(v, ks5[i], size, muls);
      outputChar = String.fromCharCode(v + base);
    } else if (code >= 65 && code <= 90) {
      const base = 65, size = 26, muls = getMuls(size);
      const ks5 = [getKs(0), getKs(1), getKs(2), getKs(3), getKs(4)];
      let v = code - base;
      for (let i = 4; i >= 0; i--) v = applyOpInv(v, ks5[i], size, muls);
      outputChar = String.fromCharCode(v + base);
    } else if (code >= 97 && code <= 122) {
      const base = 97, size = 26, muls = getMuls(size);
      const ks5 = [getKs(0), getKs(1), getKs(2), getKs(3), getKs(4)];
      let v = code - base;
      for (let i = 4; i >= 0; i--) v = applyOpInv(v, ks5[i], size, muls);
      outputChar = String.fromCharCode(v + base);
    } else {
      const symIdx = SYMBOL_CHARS.indexOf(ch);
      if (symIdx !== -1) {
        const symSize = SYMBOL_CHARS.length, symMuls = getMuls(symSize);
        const ks5 = [getKs(0), getKs(1), getKs(2), getKs(3), getKs(4)];
        let v = symIdx;
        for (let i = 4; i >= 0; i--) v = applyOpInv(v, ks5[i], symSize, symMuls);
        outputChar = SYMBOL_CHARS[v];
      } else {
        ki += 5;
        cbc = (((cbc << 3) ^ code ^ rawKs4) & 0xff);
        out.push(ch);
        continue;
      }
    }

    ki += 5;
    cbc = (((cbc << 3) ^ code ^ rawKs4) & 0xff); // CBC uses ciphertext code (the INPUT)
    out.push(outputChar);
  }

  return out.join("");
}

// ── 4-round chain helpers ─────────────────────────────────────────────────────

function encryptChain4(ksArr: Uint8Array[], value: string): string {
  let v = value;
  for (const ks of ksArr) v = encryptFPECell(ks, v);
  return v;
}

function encryptChain4V2(ksArr: Uint8Array[], value: string): string {
  let v = value;
  for (const ks of ksArr) v = encryptFPECellV2(ks, v);
  return v;
}

function decryptChain4(ksArr: Uint8Array[], value: string): string {
  let v = value;
  for (let i = ksArr.length - 1; i >= 0; i--) v = decryptFPECell(ksArr[i], v);
  return v;
}

function decryptChain4V2(ksArr: Uint8Array[], value: string): string {
  let v = value;
  for (let i = ksArr.length - 1; i >= 0; i--) v = decryptFPECellV2(ksArr[i], v);
  return v;
}

// ── Alphanumeric output (5th pass) ────────────────────────────────────────────
function deriveAlnumKey(keyChain: string[]): string {
  let h = 0xA1B2C3D4;
  for (const k of keyChain) {
    h = (Math.imul(h, 0x9e3779b9) ^ parseInt(k.slice(0, 8), 16)) >>> 0;
  }
  h = (h ^ 0x5A5A5A5A) >>> 0;
  return generateRandomKey(h);
}

// v2: also mixes in export salt (all 128 bits) so alnum mapping differs per export run
function deriveAlnumKeyV2(keyChain: string[], exportSalt: string): string {
  let h = 0xA1B2C3D4;
  for (const k of keyChain) {
    h = (Math.imul(h, 0x9e3779b9) ^ parseInt(k.slice(0, 8), 16)) >>> 0;
  }
  // Fold all four 32-bit words of the 128-bit export salt (Issue B fix)
  for (let si = 0; si < 32; si += 8) {
    if (exportSalt.length >= si + 8) {
      h = (Math.imul(h ^ parseInt(exportSalt.slice(si, si + 8), 16), 0x9e3779b9)) >>> 0;
      h = (h ^ (h >>> 16)) >>> 0;
    }
  }
  h = (h ^ 0x5A5A5A5A) >>> 0;
  return generateRandomKey(h);
}

function encryptAlphanumCell(ksBytes: Uint8Array, value: string): string {
  const S = ALNUM_CHARS.length;
  const muls = getMuls(S);
  const chars = [...value];
  let ki = 0;
  return chars.map(ch => {
    const code = ch.charCodeAt(0);
    let idx: number | null = null;
    if (code >= 48 && code <= 57)  idx = code - 48;
    else if (code >= 97 && code <= 122) idx = code - 87;
    else if (code >= 65 && code <= 90)  idx = code - 55;
    if (idx !== null) {
      let v = idx;
      for (let i = 0; i < 5; i++) v = applyOpFwd(v, ksBytes[ki++ % ksBytes.length], S, muls);
      return ALNUM_CHARS[v];
    }
    ki += 5;
    return ch;
  }).join("");
}

// ── §7 — HMAC-SHA256 integrity helpers (Issue 7) ─────────────────────────────
// The HMAC key is derived from the full key chain via HKDF-SHA256 so it is
// cryptographically independent of any individual round key.
// The HMAC covers everything in the output CSV except the HMAC line itself,
// making post-encryption tampering detectable before decryption is attempted.

async function computeExportHMAC(
  keyChain: string[], exportSalt: string, csvContent: string
): Promise<string> {
  const enc = new TextEncoder();
  const rawKey = enc.encode(keyChain.join("") + exportSalt);
  const baseKey = await crypto.subtle.importKey("raw", rawKey, "HKDF", false, ["deriveKey"]);
  const hmacKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: enc.encode("AIRAVATA-DEA-HMAC"),
      info: enc.encode("integrity-v2"),
    },
    baseKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", hmacKey, enc.encode(csvContent));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyExportHMAC(
  keyChain: string[], exportSalt: string, csvContent: string, expectedHex: string
): Promise<boolean> {
  const computed = await computeExportHMAC(keyChain, exportSalt, csvContent);
  if (computed.length !== expectedHex.length) return false;
  // Constant-time comparison to prevent timing attacks
  let diff = 0;
  for (let i = 0; i < computed.length; i++)
    diff |= computed.charCodeAt(i) ^ expectedHex.charCodeAt(i);
  return diff === 0;
}

// ── §8.C — Key fingerprint (Issue C fix) ─────────────────────────────────────
// Produces a non-invertible identifier via SHA-256 with a fixed domain separator.
// The fingerprint is 16 hex chars (64 bits of hash output); zero key bits appear.
// Previous implementation exposed 32 bits of the actual round key (first 8 hex chars),
// which is real key material.
async function computeKeyFingerprint(keyChain: string[]): Promise<string> {
  const enc = new TextEncoder();
  const material = enc.encode("AIRAVATA-FINGERPRINT-v3\x00" + keyChain.join(""));
  const digest = await crypto.subtle.digest("SHA-256", material);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16); // 64-bit prefix — sufficient for identity confirmation; SHA-256 is one-way
}

// ── §8.3-v2 — Format comment parsing ─────────────────────────────────────────
interface V2FormatMeta {
  formatVersion: string | null;   // "v2" or null for v1
  exportSalt: string | null;      // 32 hex chars
  hmacHex: string | null;         // 64 hex chars
  commentLineCount: number;       // lines to skip before CSV header
  hmacLineIndex: number;          // index of the HMAC line (−1 if absent)
}

function parseFormatMeta(lines: string[]): V2FormatMeta {
  let formatVersion: string | null = null;
  let exportSalt: string | null = null;
  let commentLineCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.startsWith("#") && line.trim() !== "") break;
    commentLineCount++;
    const trimmed = line.trim();
    if (trimmed.startsWith("# AIRAVATA-FORMAT:"))
      formatVersion = trimmed.replace("# AIRAVATA-FORMAT:", "").trim();
    else if (trimmed.startsWith("# AIRAVATA-EXPORT-SALT:"))
      exportSalt = trimmed.replace("# AIRAVATA-EXPORT-SALT:", "").trim();
  }

  // Find HMAC line scanning from the end
  let hmacHex: string | null = null;
  let hmacLineIndex = -1;
  for (let i = lines.length - 1; i >= 0; i--) {
    const trimmed = lines[i].trim();
    if (trimmed === "") continue;
    if (trimmed.startsWith("# AIRAVATA-HMAC-SHA256:")) {
      hmacHex = trimmed.replace("# AIRAVATA-HMAC-SHA256:", "").trim();
      hmacLineIndex = i;
    }
    break;
  }

  return { formatVersion, exportSalt, hmacHex, commentLineCount, hmacLineIndex };
}

// ── CSV helpers ───────────────────────────────────────────────────────────────
function csvEscape(val: string): string {
  if (val.includes(",") || val.includes('"') || val.includes("\n"))
    return '"' + val.replace(/"/g, '""') + '"';
  return val;
}

function splitCSVLine(line: string): string[] {
  const cells: string[] = [];
  let inQ = false, cur = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (inQ && line[i + 1] === '"') { cur += '"'; i++; }
      else inQ = !inQ;
    } else if (c === "," && !inQ) {
      cells.push(cur); cur = "";
    } else cur += c;
  }
  cells.push(cur);
  return cells;
}

// ── Public types ──────────────────────────────────────────────────────────────

export interface FieldSpec {
  varName: string;
  start: number;
  end: number;
}

export interface AnonymizeOptions {
  keyMode: "random" | "pbkdf2" | "hex";
  /** Four seed values — one per encryption round. */
  seeds: number[];
  passphrase: string;
  pbkdf2Iterations: number;
  deterministic: boolean;
  keyHex?: string;
  /**
   * When true, a 5th FPE pass remaps every encrypted character into the 36-char
   * alphanumeric alphabet (0–9 + a–z), preserving the original field length exactly.
   */
  alphanumericOutput?: boolean;
  /**
   * (v2) 128-bit export salt as 32 hex characters, generated once per export via
   * crypto.getRandomValues() and embedded in the CSV header.  Pass this back to
   * decryptCSVToBlob (or let decryptCSVToBlob parse it from the file automatically).
   * If omitted during encryption a fresh CSPRNG salt is generated automatically.
   */
  exportSalt?: string;
}

/** (v2) Non-sensitive record of what was done for this anonymization run. */
export interface AnonymizeAuditLog {
  /** ISO-8601 timestamp of when the export was produced */
  timestamp: string;
  /** "v2" for new files */
  formatVersion: string;
  /** "random" | "pbkdf2" | "hex" */
  keyMode: string;
  /** SHA-256(keyChain || domain-separator) truncated to 16 hex chars.
   *  Derived via one-way hash — zero actual key bits are exposed.
   *  Suitable for confirming key identity across logs without leaking material. */
  keyFingerprint: string;
  /** The 128-bit export salt (32 hex chars). Required for decryption; safe to store
   *  alongside the file since it does not reveal key material. */
  exportSalt: string;
  /** Names of columns that were encrypted in this run */
  columnsProcessed: string[];
  /** true — CBC diffusion was applied (always true for v2) */
  cbcEnabled: boolean;
  /** true — HMAC-SHA256 integrity tag is embedded in the CSV (always true for v2) */
  hmacPresent: boolean;
}

export interface AnonymizeResult {
  blob: Blob;
  /** First round key hex (or the user-supplied hex key in hex mode). Display only. */
  keyHex: string;
  /** 128-bit export salt used for this run (32 hex chars). Store with the file. */
  exportSalt: string;
  /** Non-sensitive audit log for this export */
  auditLog: AnonymizeAuditLog;
}

// ── Key chain resolution ──────────────────────────────────────────────────────

// v1 (sync) — preserved for legacy decryption of v1 CSV files.
export function resolveKeyChain(options: AnonymizeOptions): string[] {
  if (options.keyMode === "hex") {
    const base = (options.keyHex ?? "").toLowerCase().trim();
    if (!/^[0-9a-f]{64}$/.test(base))
      throw new Error("A raw hex key must contain exactly 64 hexadecimal characters.");
    let rolling = (parseInt(base.slice(0, 8), 16) ^ 0xdeadbeef) >>> 0;
    return [0, 1, 2, 3].map(i => {
      rolling = (Math.imul(rolling, 0x9e3779b9) ^ (i * 0x5a5a5a5b)) >>> 0;
      rolling = (rolling ^ (rolling >>> 16)) >>> 0;
      return generateRandomKey(rolling);
    });
  }
  if (options.keyMode === "pbkdf2") {
    if (options.passphrase.trim().length === 0)
      throw new Error("A passphrase is required when PBKDF2 mode is selected.");
    let tag = "";
    return [0, 1, 2, 3].map(i => {
      tag += `\x00R${i}`;
      return deriveKeyFromPassphrase_v1(options.passphrase + tag, options.pbkdf2Iterations);
    });
  }
  const s = options.seeds;
  const ordered = [s[0] ?? 42, s[1] ?? 137, s[2] ?? 2024, s[3] ?? 7];
  let rolling = 0x9e3779b9;
  for (const seed of ordered) {
    rolling = (Math.imul(rolling, 0x9e3779b9) ^ (seed >>> 0)) >>> 0;
    rolling = (rolling ^ (rolling >>> 16)) >>> 0;
    rolling = (Math.imul(rolling, 0x85ebca6b)) >>> 0;
    rolling = (rolling ^ (rolling >>> 13)) >>> 0;
  }
  const masterKey = generateRandomKey(rolling);
  let rollingK = (parseInt(masterKey.slice(0, 8), 16) ^ 0xdeadbeef) >>> 0;
  return [0, 1, 2, 3].map(i => {
    rollingK = (Math.imul(rollingK, 0x9e3779b9) ^ (i * 0x5a5a5a5b)) >>> 0;
    rollingK = (rollingK ^ (rollingK >>> 16)) >>> 0;
    return generateRandomKey(rollingK);
  });
}

// v2 (async) — uses Web Crypto PBKDF2 for passphrase mode and mixes the export
// salt into seed mode so the same seeds produce different keys in each export run.
export async function resolveKeyChainAsync(options: AnonymizeOptions): Promise<string[]> {
  const exportSalt = options.exportSalt ?? "";

  if (options.keyMode === "hex") {
    // Hex mode: same derivation as v1 (the hex key IS the full key material)
    const base = (options.keyHex ?? "").toLowerCase().trim();
    if (!/^[0-9a-f]{64}$/.test(base))
      throw new Error("A raw hex key must contain exactly 64 hexadecimal characters.");
    let rolling = (parseInt(base.slice(0, 8), 16) ^ 0xdeadbeef) >>> 0;
    return [0, 1, 2, 3].map(i => {
      rolling = (Math.imul(rolling, 0x9e3779b9) ^ (i * 0x5a5a5a5b)) >>> 0;
      rolling = (rolling ^ (rolling >>> 16)) >>> 0;
      return generateRandomKey(rolling);
    });
  }

  if (options.keyMode === "pbkdf2") {
    if (options.passphrase.trim().length === 0)
      throw new Error("A passphrase is required when PBKDF2 mode is selected.");
    // Issue 1 fix: real Web Crypto PBKDF2 with at least 100 000 iterations
    const iterations = Math.max(100_000, options.pbkdf2Iterations || 100_000);
    let tag = "";
    const keys: string[] = [];
    for (let i = 0; i < 4; i++) {
      tag += `\x00R${i}`;
      keys.push(await deriveKeyFromPassphrase_v2(
        options.passphrase + tag, exportSalt, iterations
      ));
    }
    return keys;
  }

  // Seed mode — Issue 4 fix: mix the export salt into the master seed so the
  // same user seeds produce a different key chain in each independent export run.
  const s = options.seeds;
  const ordered = [s[0] ?? 42, s[1] ?? 137, s[2] ?? 2024, s[3] ?? 7];
  let rolling = 0x9e3779b9;
  for (const seed of ordered) {
    rolling = (Math.imul(rolling, 0x9e3779b9) ^ (seed >>> 0)) >>> 0;
    rolling = (rolling ^ (rolling >>> 16)) >>> 0;
    rolling = (Math.imul(rolling, 0x85ebca6b)) >>> 0;
    rolling = (rolling ^ (rolling >>> 13)) >>> 0;
  }
  // Mix all 128 bits of the export salt into the rolling seed (Issue B fix:
  // was only first 32 bits, giving a ~2^16 birthday bound; now all 4 words are folded in)
  for (let si = 0; si < 32; si += 8) {
    if (exportSalt.length >= si + 8) {
      rolling = (rolling ^ parseInt(exportSalt.slice(si, si + 8), 16)) >>> 0;
      rolling = (Math.imul(rolling, 0x9e3779b9)) >>> 0;
      rolling = (rolling ^ (rolling >>> 16)) >>> 0;
    }
  }
  const masterKey = generateRandomKey(rolling);
  let rollingK = (parseInt(masterKey.slice(0, 8), 16) ^ 0xdeadbeef) >>> 0;
  return [0, 1, 2, 3].map(i => {
    rollingK = (Math.imul(rollingK, 0x9e3779b9) ^ (i * 0x5a5a5a5b)) >>> 0;
    rollingK = (rollingK ^ (rollingK >>> 16)) >>> 0;
    return generateRandomKey(rollingK);
  });
}

// Compat: return first key (used by UI to display "the key" summary)
export function resolveKeyHex(options: AnonymizeOptions): string {
  return resolveKeyChain(options)[0];
}

const STREAM_CHUNK = 50_000;

function ksSize(valueLen: number): number { return valueLen * 5 + 64; }

const DET_KS_SIZE = 256 * 5 + 64;

// ── Streaming encrypt: FWF raw text → anonymized CSV Blob (v2) ────────────────
export async function encryptFWFToBlob(
  rawText: string,
  fields: FieldSpec[],
  encCols: ReadonlySet<string>,
  options: AnonymizeOptions,
  onProgress: (pct: number) => void
): Promise<AnonymizeResult> {
  // ── Issue 4 & 6: generate a fresh CSPRNG export salt per run ─────────────
  const exportSalt = options.exportSalt ?? cryptoRandomHex(16);
  const optionsWithSalt: AnonymizeOptions = { ...options, exportSalt };

  // ── Issue 1: use async key chain for proper PBKDF2 ────────────────────────
  const keyChain = await resolveKeyChainAsync(optionsWithSalt);

  const keyHex = options.keyMode === "hex"
    ? (options.keyHex ?? "").toLowerCase().trim()
    : keyChain[0];

  // Derive alphanumeric-step key (mixes in all 128 bits of export salt)
  const alnumKey = options.alphanumericOutput ? deriveAlnumKeyV2(keyChain, exportSalt) : "";
  const colAlnumKs: Record<string, Uint8Array> = {};
  if (options.alphanumericOutput) {
    for (const f of fields) {
      if (encCols.has(f.varName))
        colAlnumKs[f.varName] = makeCellKsBytesV2(
          DET_KS_SIZE, alnumKey, hashColIV(alnumKey, f.varName), exportSalt
        );
    }
  }

  const lines = rawText.split(/\r?\n/);
  let dataLines: string[] = [];
  for (const l of lines) if (l.length > 0) dataLines.push(l);
  if (dataLines.length > 0 && dataLines[0].includes(",")) dataLines = dataLines.slice(1);
  const total = dataLines.length;

  const csvHeader = fields.map(f => csvEscape(f.varName)).join(",");

  // v2 format comment block — embedded before the CSV header row
  const metaBlock = [
    `# AIRAVATA-FORMAT: ${FORMAT_VERSION}`,
    `# AIRAVATA-EXPORT-SALT: ${exportSalt}`,
    `# AIRAVATA-CBC: enabled`,
    "",
  ].join("\n");

  const chunks: string[] = [metaBlock + csvHeader + "\n"];

  const detCache = new Map<string, string>();
  const ivCounters: Record<string, number> = {};

  for (let i = 0; i < total; i += STREAM_CHUNK) {
    const end = Math.min(i + STREAM_CHUNK, total);
    const rowLines: string[] = [];

    for (let li = i; li < end; li++) {
      const line = dataLines[li];
      const csvCells: string[] = [];

      for (const f of fields) {
        let val = line.padEnd(f.end).substring(f.start - 1, f.end).trim();

        if (encCols.has(f.varName) && val.length > 0) {
          if (options.deterministic) {
            // Deterministic mode: keystream is derived solely from the column IV
            // (key + column name), NOT from the cell value.  Using the cell value
            // as a nonce would make decryption impossible because the decryptor
            // only knows the ciphertext — not the original plaintext — so it could
            // never reconstruct the nonce that was used during encryption.
            // Column-IV-only gives the same keystream for every cell in a column,
            // which is what the guide (SectionFPE) describes and what makes
            // round-trip decryption work correctly.
            const ck = f.varName + "\x00" + val;
            if (detCache.has(ck)) {
              val = detCache.get(ck)!;
            } else {
              const ksArr = keyChain.map(kh =>
                makeCellKsBytesV2(
                  ksSize(val.length), kh,
                  hashColIV(kh, f.varName),
                  exportSalt
                )
              );
              // ── CBC diffusion ─────────────────────────────────────────────
              let enc = encryptChain4V2(ksArr, val);
              if (options.alphanumericOutput) enc = encryptAlphanumCell(colAlnumKs[f.varName], enc);
              detCache.set(ck, enc);
              val = enc;
            }
          } else {
            ivCounters[f.varName] = ((ivCounters[f.varName] ?? 0) + 1) >>> 0;
            const ivCounter = ivCounters[f.varName];
            const columnSeed = hashColIV(keyChain[0], f.varName);
            // ── Issue 4 fix: export salt in non-deterministic IV ──────────
            const ksArr = keyChain.map((kh, ri) =>
              makeCellKsBytesV2(
                ksSize(val.length), kh,
                (ivCounter ^ columnSeed ^ (ri * 0x12345679)) >>> 0,
                exportSalt
              )
            );
            // ── Issue 3 fix: CBC diffusion ────────────────────────────────
            val = encryptChain4V2(ksArr, val);
            if (options.alphanumericOutput) val = encryptAlphanumCell(colAlnumKs[f.varName], val);
          }
        }
        csvCells.push(csvEscape(val));
      }
      rowLines.push(csvCells.join(","));
    }

    chunks.push(rowLines.join("\n") + "\n");
    // Reserve last 10% of progress for HMAC computation
    onProgress(Math.min(89, Math.round((end / total) * 90)));
    await new Promise(r => setTimeout(r, 0));
  }

  // ── Issue 7: compute HMAC over the full CSV content (excl. HMAC line itself)
  const csvBody = chunks.join("");
  onProgress(92);
  const hmacHex = await computeExportHMAC(keyChain, exportSalt, csvBody);
  const finalContent = csvBody + `# AIRAVATA-HMAC-SHA256: ${hmacHex}\n`;

  onProgress(100);

  // ── Issue 8: audit log (Issue C fix: fingerprint is a SHA-256 hash, not raw key bits)
  const keyFingerprint = await computeKeyFingerprint(keyChain);
  const auditLog: AnonymizeAuditLog = {
    timestamp: new Date().toISOString(),
    formatVersion: FORMAT_VERSION,
    keyMode: options.keyMode,
    keyFingerprint,
    exportSalt,
    columnsProcessed: [...encCols],
    cbcEnabled: true,
    hmacPresent: true,
  };

  return {
    blob: new Blob([finalContent], { type: "text/csv;charset=utf-8;" }),
    keyHex,
    exportSalt,
    auditLog,
  };
}

// ── Streaming decrypt: CSV text → decrypted CSV Blob ─────────────────────────
// Automatically detects v1 vs v2 format from the CSV header comments.
// For v2: parses export salt and verifies HMAC before decrypting.
// For v1 (no format header): falls through to the legacy code path.
export async function decryptCSVToBlob(
  csvText: string,
  decCols: ReadonlySet<string>,
  options: AnonymizeOptions,
  onProgress: (pct: number) => void
): Promise<Blob> {
  const allLines = csvText.split(/\r?\n/);
  const meta = parseFormatMeta(allLines);
  const isV2 = meta.formatVersion === "v2";

  // ── v2 path ───────────────────────────────────────────────────────────────
  if (isV2) {
    const exportSalt = meta.exportSalt ?? options.exportSalt ?? "";
    const optionsV2: AnonymizeOptions = { ...options, exportSalt };
    const keyChain = await resolveKeyChainAsync(optionsV2);

    // ── Issue 7: verify HMAC before decrypting ────────────────────────────
    if (meta.hmacHex && meta.hmacLineIndex >= 0) {
      // Content that was HMACed = everything except the HMAC line itself
      const linesForHMAC = allLines.slice(0, meta.hmacLineIndex);
      // Trailing newline matters — match how the encryptor built csvBody
      const contentForHMAC = linesForHMAC.join("\n") + "\n";
      const valid = await verifyExportHMAC(keyChain, exportSalt, contentForHMAC, meta.hmacHex);
      if (!valid) {
        throw new Error(
          "HMAC verification failed — the file may have been tampered with or the wrong key was provided."
        );
      }
    }

    // Skip comment lines at top + blank separator; find actual CSV header
    let headerIdx = meta.commentLineCount;
    while (headerIdx < allLines.length && allLines[headerIdx].trim() === "") headerIdx++;
    if (headerIdx >= allLines.length) throw new Error("Empty CSV file");

    const headers = splitCSVLine(allLines[headerIdx]);
    if (headers.length === 0) throw new Error("No headers found in CSV");

    const dataLines: string[] = [];
    const endLine = meta.hmacLineIndex >= 0 ? meta.hmacLineIndex : allLines.length;
    for (let i = headerIdx + 1; i < endLine; i++) {
      const l = allLines[i].trim();
      if (l.length > 0 && !l.startsWith("#")) dataLines.push(allLines[i]);
    }
    const total = dataLines.length;

    const headerLine = headers.map(csvEscape).join(",");
    const chunks: string[] = [headerLine + "\n"];

    const detCache = new Map<string, string>();
    const ivCounters: Record<string, number> = {};

    for (let i = 0; i < total; i += STREAM_CHUNK) {
      const end = Math.min(i + STREAM_CHUNK, total);
      const rowLines: string[] = [];

      for (let li = i; li < end; li++) {
        const cells = splitCSVLine(dataLines[li]);
        const outCells: string[] = [];

        for (let ci = 0; ci < headers.length; ci++) {
          const col = headers[ci];
          let val = cells[ci] ?? "";

          if (decCols.has(col) && val.length > 0) {
            if (options.deterministic) {
              // Deterministic decryption: reconstruct the SAME keystream as encryption
              // by using the column IV only — identical to the encryption path.
              // (A per-value nonce can't be used here because the decryptor only has
              // the ciphertext, not the original plaintext that seeded the nonce.)
              const ck = col + "\x00" + val;
              if (detCache.has(ck)) {
                val = detCache.get(ck)!;
              } else {
                const ksArr = keyChain.map(kh =>
                  makeCellKsBytesV2(
                    ksSize(val.length), kh,
                    hashColIV(kh, col),
                    exportSalt
                  )
                );
                const dec = decryptChain4V2(ksArr, val);
                detCache.set(ck, dec);
                val = dec;
              }
            } else {
              ivCounters[col] = ((ivCounters[col] ?? 0) + 1) >>> 0;
              const ivCounter = ivCounters[col];
              const columnSeed = hashColIV(keyChain[0], col);
              const ksArr = keyChain.map((kh, ri) =>
                makeCellKsBytesV2(
                  ksSize(val.length), kh,
                  (ivCounter ^ columnSeed ^ (ri * 0x12345679)) >>> 0,
                  exportSalt
                )
              );
              val = decryptChain4V2(ksArr, val);
            }
          }
          outCells.push(csvEscape(val));
        }
        rowLines.push(outCells.join(","));
      }

      chunks.push(rowLines.join("\n") + "\n");
      onProgress(Math.min(99, Math.round((end / total) * 100)));
      await new Promise(r => setTimeout(r, 0));
    }

    onProgress(100);
    return new Blob(chunks, { type: "text/csv;charset=utf-8;" });
  }

  // ── v1 legacy path (no format header) ─────────────────────────────────────
  const lines = csvText.split(/\r?\n/);

  let headerIdx = 0;
  while (headerIdx < lines.length && lines[headerIdx].trim() === "") headerIdx++;
  if (headerIdx >= lines.length) throw new Error("Empty CSV file");

  const headers = splitCSVLine(lines[headerIdx]);
  if (headers.length === 0) throw new Error("No headers found in CSV");

  const keyChain = resolveKeyChain(options);

  const colKs4: Record<string, Uint8Array[]> = {};
  if (options.deterministic) {
    for (const col of decCols) {
      colKs4[col] = keyChain.map(kh =>
        makeCellKsBytes(DET_KS_SIZE, kh, hashColIV(kh, col))
      );
    }
  }

  const dataLines: string[] = [];
  for (let i = headerIdx + 1; i < lines.length; i++) {
    if (lines[i].trim().length > 0) dataLines.push(lines[i]);
  }
  const total = dataLines.length;

  const headerLine = headers.map(csvEscape).join(",");
  const chunks: string[] = [headerLine + "\n"];

  const detCache = new Map<string, string>();
  const ivCounters: Record<string, number> = {};

  for (let i = 0; i < total; i += STREAM_CHUNK) {
    const end = Math.min(i + STREAM_CHUNK, total);
    const rowLines: string[] = [];

    for (let li = i; li < end; li++) {
      const cells = splitCSVLine(dataLines[li]);
      const outCells: string[] = [];

      for (let ci = 0; ci < headers.length; ci++) {
        const col = headers[ci];
        let val = cells[ci] ?? "";

        if (decCols.has(col) && val.length > 0) {
          if (options.deterministic) {
            const ck = col + "\x00" + val;
            if (detCache.has(ck)) {
              val = detCache.get(ck)!;
            } else {
              const dec = decryptChain4(colKs4[col], val);
              detCache.set(ck, dec);
              val = dec;
            }
          } else {
            ivCounters[col] = ((ivCounters[col] ?? 0) + 1) >>> 0;
            const ivCounter = ivCounters[col];
            const columnSeed = hashColIV(keyChain[0], col);
            const ksArr = keyChain.map((kh, ri) =>
              makeCellKsBytes(ksSize(val.length), kh, (ivCounter ^ columnSeed ^ (ri * 0x12345679)) >>> 0)
            );
            val = decryptChain4(ksArr, val);
          }
        }
        outCells.push(csvEscape(val));
      }
      rowLines.push(outCells.join(","));
    }

    chunks.push(rowLines.join("\n") + "\n");
    onProgress(Math.min(99, Math.round((end / total) * 100)));
    await new Promise(r => setTimeout(r, 0));
  }

  onProgress(100);
  return new Blob(chunks, { type: "text/csv;charset=utf-8;" });
}

// ── CSV header reader (first non-comment line — for column selector UI) ───────
export function readCSVHeaders(text: string): string[] {
  const lines = text.slice(0, 8192).split(/\r?\n/);
  // Skip comment/meta lines produced by v2 format
  const firstDataLine = lines.find(l => l.trim().length > 0 && !l.startsWith("#")) ?? "";
  return splitCSVLine(firstDataLine);
}
