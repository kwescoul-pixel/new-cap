'use strict';

/**
 * FriendlyCaptcha Puzzle Solver — Node.js implementation
 *
 * Solves FriendlyCaptcha proof-of-work puzzles using Blake2b-256.
 * Uses WebAssembly for speed, with a pure-JS fallback.
 * The heavy computation runs in a Node.js Worker Thread so the main
 * thread stays non-blocking.
 *
 * Token format (compatible with friendly-challenge v0.9.12 widget):
 *   frc-captcha-solution = "<signature>.<puzzleBase64>.<solutionBase64>.<diagnosticsBase64>"
 *
 * Usage (script):
 *   node cap.js [sitekey]
 *
 * Usage (module):
 *   const { fetchAndSolvePuzzle, solvePuzzleString } = require('./cap');
 */

const { Worker, isMainThread, parentPort } = require('worker_threads');
const path = require('path');
const https = require('https');
const fs = require('fs');

// ─────────────────────────────────────────────────────────────────────────────
// Blake2b — pure JavaScript implementation (32-bit arithmetic on 64-bit words)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Blake2b Initialization Vectors — low and high 32-bit halves of the 8 IVs.
 * (fractional parts of the square roots of the first 8 primes, 64-bit each)
 */
const BLAKE2B_IV32 = [
  0xF3BCC908, 0x6A09E667,  // IV[0]
  0x84CAA73B, 0xBB67AE85,  // IV[1]
  0xFE94F82B, 0x3C6EF372,  // IV[2]
  0x5F1D36F1, 0xA54FF53A,  // IV[3]
  0xADE682D1, 0x510E527F,  // IV[4]
  0x2B3E6C1F, 0x9B05688C,  // IV[5]
  0xFB41BD6B, 0x1F83D9AB,  // IV[6]
  0x137E2179, 0x5BE0CD19   // IV[7]
];

/**
 * Blake2b sigma permutation table.
 * 12 rounds × 16 indices per round.
 * Each index points to a 32-bit word pair in the message array
 * (i.e. values are 2× the standard Blake2b sigma for 32-bit pair indexing).
 */
const BLAKE2B_SIGMA = [
   0,  2,  4,  6,  8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, // round  0
  28, 20,  8, 16, 18, 30, 26, 12,  2, 24,  0,  4, 22, 14, 10,  6, // round  1
  22, 16, 24,  0, 10,  4, 30, 26, 20, 28,  6, 12, 14,  2, 18,  8, // round  2
  14, 18,  6,  2, 26, 24, 22, 28,  4, 12, 10, 20,  8,  0, 30, 16, // round  3
  18,  0, 10, 14,  4,  8, 20, 30, 28,  2, 22, 24, 12, 16,  6, 26, // round  4
   4, 24, 12, 20,  0, 22, 16,  6,  8, 26, 14, 10, 30, 28,  2, 18, // round  5
  24, 10,  2, 30, 28, 26,  8, 20,  0, 14, 12,  6, 18,  4, 16, 22, // round  6
  26, 22, 14, 28, 24,  2,  6, 18, 10,  0, 30,  8, 16, 12,  4, 20, // round  7
  12, 30, 28, 18, 22,  6,  0, 16, 24,  4, 26, 14,  2,  8, 20, 10, // round  8
  20,  4, 16,  8, 14, 12,  2, 10, 30, 22, 18, 28,  6, 24, 26,  0, // round  9
   0,  2,  4,  6,  8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, // round 10
  28, 20,  8, 16, 18, 30, 26, 12,  2, 24,  0,  4, 22, 14, 10,  6  // round 11
];

/** Holds the mutable state for one Blake2b-256 computation. */
class Blake2bState {
  /**
   * @param {number} outputLength - desired hash output length in bytes (32 for Blake2b-256)
   */
  constructor(outputLength) {
    /** 128-byte input block (single block, since puzzles are always 128 bytes). */
    this.inputBlock = new Uint8Array(128);
    /** Hash state: 8 × 64-bit words stored as 16 × uint32 (low, high). */
    this.hashWords = new Uint32Array(16);
    /** Total bytes hashed so far (always 128 for single-block puzzle inputs). */
    this.totalBytesHashed = 0;
    /** Working vector v0..v15 for compression (16 × 64-bit as 32 × uint32). */
    this.workingVector = new Uint32Array(32);
    /** Message schedule m0..m15 (16 × 64-bit as 32 × uint32). */
    this.messageSchedule = new Uint32Array(32);
    /** Output length in bytes. */
    this.outputLength = outputLength;
  }
}

/**
 * Reads 4 bytes from `buf` at `offset` as a little-endian uint32.
 * @param {Uint8Array} buf
 * @param {number} offset
 * @returns {number}
 */
function readUint32LE(buf, offset) {
  return buf[offset] ^ buf[offset + 1] << 8 ^ buf[offset + 2] << 16 ^ buf[offset + 3] << 24;
}

/**
 * Blake2b G mixing function (operates on 32-bit word pairs representing 64-bit values).
 *
 * @param {Uint32Array} workVec   - 32-element working vector (v0..v15, 2 uint32 per word)
 * @param {Uint32Array} msgWords  - 32 message words (m0..m15 as 32-bit pairs)
 * @param {number} a - index of v_a in workVec
 * @param {number} b - index of v_b in workVec
 * @param {number} c - index of v_c in workVec
 * @param {number} d - index of v_d in workVec
 * @param {number} xIdx - index of message word x in msgWords (sigma low)
 * @param {number} yIdx - index of message word y in msgWords (sigma high)
 */
function blake2bMix(workVec, msgWords, a, b, c, d, xIdx, yIdx) {
  const xLo = msgWords[xIdx],     xHi = msgWords[xIdx + 1];
  const yLo = msgWords[yIdx],     yHi = msgWords[yIdx + 1];

  let aLo = workVec[a],   aHi = workVec[a + 1];
  let bLo = workVec[b],   bHi = workVec[b + 1];
  let cLo = workVec[c],   cHi = workVec[c + 1];
  let dLo = workVec[d],   dHi = workVec[d + 1];

  let sum, carry, xorLo, xorHi;

  // v_a = v_a + v_b + x
  sum = aLo + bLo; carry = (aLo & bLo | (aLo | bLo) & ~sum) >>> 31;
  aLo = sum;       aHi = aHi + bHi + carry;
  sum = aLo + xLo; carry = (aLo & xLo | (aLo | xLo) & ~sum) >>> 31;
  aLo = sum;       aHi = aHi + xHi + carry;

  // v_d = rotr64(v_d ^ v_a, 32)  — swap the two 32-bit halves
  xorLo = dLo ^ aLo; xorHi = dHi ^ aHi;
  dLo = xorHi;        dHi = xorLo;

  // v_c = v_c + v_d
  sum = cLo + dLo; carry = (cLo & dLo | (cLo | dLo) & ~sum) >>> 31;
  cLo = sum;       cHi = cHi + dHi + carry;

  // v_b = rotr64(v_b ^ v_c, 24)
  xorLo = bLo ^ cLo; xorHi = bHi ^ cHi;
  bLo = xorLo >>> 24 ^ xorHi << 8;
  bHi = xorHi >>> 24 ^ xorLo << 8;

  // v_a = v_a + v_b + y
  sum = aLo + bLo; carry = (aLo & bLo | (aLo | bLo) & ~sum) >>> 31;
  aLo = sum;       aHi = aHi + bHi + carry;
  sum = aLo + yLo; carry = (aLo & yLo | (aLo | yLo) & ~sum) >>> 31;
  aLo = sum;       aHi = aHi + yHi + carry;

  // v_d = rotr64(v_d ^ v_a, 16)
  xorLo = dLo ^ aLo; xorHi = dHi ^ aHi;
  dLo = xorLo >>> 16 ^ xorHi << 16;
  dHi = xorHi >>> 16 ^ xorLo << 16;

  // v_c = v_c + v_d
  sum = cLo + dLo; carry = (cLo & dLo | (cLo | dLo) & ~sum) >>> 31;
  cLo = sum;       cHi = cHi + dHi + carry;

  // v_b = rotr64(v_b ^ v_c, 63)
  xorLo = bLo ^ cLo; xorHi = bHi ^ cHi;
  bLo = xorHi >>> 31 ^ xorLo << 1;
  bHi = xorLo >>> 31 ^ xorHi << 1;

  workVec[a] = aLo; workVec[a + 1] = aHi;
  workVec[b] = bLo; workVec[b + 1] = bHi;
  workVec[c] = cLo; workVec[c + 1] = cHi;
  workVec[d] = dLo; workVec[d + 1] = dHi;
}

/**
 * Blake2b compression function — mixes one 128-byte block into the hash state.
 *
 * @param {Blake2bState} state
 * @param {boolean} isFinalBlock - true when this is the last (and only) input block
 */
function blake2bCompress(state, isFinalBlock) {
  const v = state.workingVector;
  const m = state.messageSchedule;

  // Initialise working vector from hash state and IVs
  for (let i = 0; i < 16; i++) {
    v[i]      = state.hashWords[i];
    v[i + 16] = BLAKE2B_IV32[i];
  }

  // Mix in the byte counter (low 32 bits suffice — inputs are always ≤ 128 bytes)
  v[24] ^= state.totalBytesHashed;
  v[25] ^= Math.floor(state.totalBytesHashed / 4294967296); // high 32 bits (always 0)

  // Invert finalization words for the last block
  if (isFinalBlock) { v[28] = ~v[28]; v[29] = ~v[29]; }

  // Load the input block as 32 little-endian uint32 words
  for (let i = 0; i < 32; i++) m[i] = readUint32LE(state.inputBlock, 4 * i);

  // 12 rounds of column + diagonal mixing
  for (let round = 0; round < 12; round++) {
    const base = 16 * round;
    const s = BLAKE2B_SIGMA;
    // Column step
    blake2bMix(v, m,  0,  8, 16, 24, s[base +  0], s[base +  1]);
    blake2bMix(v, m,  2, 10, 18, 26, s[base +  2], s[base +  3]);
    blake2bMix(v, m,  4, 12, 20, 28, s[base +  4], s[base +  5]);
    blake2bMix(v, m,  6, 14, 22, 30, s[base +  6], s[base +  7]);
    // Diagonal step
    blake2bMix(v, m,  0, 10, 20, 30, s[base +  8], s[base +  9]);
    blake2bMix(v, m,  2, 12, 22, 24, s[base + 10], s[base + 11]);
    blake2bMix(v, m,  4, 14, 16, 26, s[base + 12], s[base + 13]);
    blake2bMix(v, m,  6,  8, 18, 28, s[base + 14], s[base + 15]);
  }

  // Finalise: XOR the working vector back into the hash state
  for (let i = 0; i < 16; i++) state.hashWords[i] ^= v[i] ^ v[i + 16];
}

/**
 * Resets a Blake2bState and loads a new 128-byte input block.
 * Uses Blake2b in hash-only mode (no key, fan-out = 1, max depth = 1).
 *
 * @param {Blake2bState} state
 * @param {Uint8Array} inputBlock - exactly 128 bytes
 */
function blake2bInitWithInput(state, inputBlock) {
  for (let i = 0; i < 16; i++) state.hashWords[i] = BLAKE2B_IV32[i];
  state.inputBlock.set(inputBlock);
  // Parameter block byte 0 = digest length, bytes 1-2 = 0x0101 (fan-out=1, depth=1)
  state.hashWords[0] ^= 0x01010000 ^ state.outputLength;
}

// ─────────────────────────────────────────────────────────────────────────────
// AssemblyScript WASM Runtime Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Wraps raw AssemblyScript WASM exports with array allocation helpers.
 * AssemblyScript uses a custom runtime that needs __alloc, __retain, etc.
 *
 * @param {WebAssembly.Exports} wasmExports
 * @returns {Object} wrapped exports augmented with __allocArray and __getUint8Array
 */
function wrapAssemblyScriptExports(wasmExports) {
  const wrapper = {};
  const memory  = wasmExports.memory;
  const alloc   = wasmExports.__alloc;
  const retain  = wasmExports.__retain;

  // Runtime type information base pointer (for array element size lookups).
  // __rtti_base is always present in AssemblyScript builds; if somehow missing,
  // we throw rather than silently using an invalid memory address.
  if (!wasmExports.__rtti_base) throw new Error('WASM is missing required __rtti_base export');
  const rttiBase = wasmExports.__rtti_base >>> 0;

  /**
   * Reads element size info for `typeId` from the RTTI table embedded in WASM memory.
   * @param {number} typeId
   */
  function getArrayElementInfo(typeId) {
    return new Uint32Array(memory.buffer)[(rttiBase + 4 >>> 2) + 2 * typeId];
  }

  /**
   * Allocates a new AssemblyScript typed array in WASM memory and fills it.
   * @param {number} typeId   - WASM type ID (e.g. exports.Uint8Array_ID)
   * @param {Uint8Array} values - initial values to copy in
   * @returns {number} pointer to the allocated array header
   */
  wrapper.__allocArray = function allocWasmArray(typeId, values) {
    const elemInfo  = getArrayElementInfo(typeId);
    const elemAlign = 31 - Math.clz32(elemInfo >>> 6 & 31);
    const length    = values.length;
    const dataPtr   = alloc(length << elemAlign, 0);
    const headerPtr = alloc(12, typeId);
    const header32  = new Uint32Array(memory.buffer);
    header32[headerPtr + 0 >>> 2] = retain(dataPtr);
    header32[headerPtr + 4 >>> 2] = dataPtr;
    header32[headerPtr + 8 >>> 2] = length << elemAlign;
    if (elemInfo & 0x4000) { // managed (reference) elements
      const mem8 = new Uint8Array(memory.buffer);
      for (let i = 0; i < length; i++) mem8[(dataPtr >>> elemAlign) + i] = retain(values[i]);
    } else {
      new Uint8Array(memory.buffer).set(values, dataPtr >>> elemAlign);
    }
    return headerPtr;
  };

  /**
   * Returns a Uint8Array view into a WASM-managed Uint8Array.
   * @param {number} ptr - array header pointer
   * @returns {Uint8Array}
   */
  wrapper.__getUint8Array = function getWasmUint8Array(ptr) {
    const mem32   = new Uint32Array(memory.buffer);
    const dataPtr = mem32[ptr + 4 >>> 2];
    const byteLen = mem32[dataPtr - 4 >>> 2] >>> 0;
    return new Uint8Array(memory.buffer, dataPtr, byteLen);
  };

  // Re-export all WASM functions, wrapping them to handle optional-argument
  // length signalling used by AssemblyScript.
  const setArgCount =
    wasmExports.__argumentsLength
      ? (n) => { wasmExports.__argumentsLength.value = n; }
      : wasmExports.__setArgumentsLength || wasmExports.__setargc || (() => {});

  for (const key of Object.keys(wasmExports)) {
    const value = wasmExports[key];
    const name  = key.split('.')[0];
    if (typeof value === 'function' && value !== setArgCount) {
      wrapper[name] = (...args) => { setArgCount(args.length); return value(...args); };
      wrapper[name].original = value;
    } else {
      wrapper[name] = value;
    }
  }

  return wrapper;
}

// ─────────────────────────────────────────────────────────────────────────────
// Solver Factory Functions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Creates a pure-JS Blake2b solver function.
 *
 * The returned solver repeatedly hashes the 128-byte `inputBuffer` while
 * incrementing the uint32 counter stored at bytes 124–127 (little-endian).
 * It returns on the first hash whose first uint32 word is below `threshold`.
 *
 * @returns {Function} (inputBuffer, threshold, maxIterations?) => [inputBuffer, hashBytes]
 */
function createJsSolver() {
  const state = new Blake2bState(32);
  state.totalBytesHashed = 128;

  return function jsSolve(inputBuffer, threshold, maxIterations = 0xFFFFFFFF) {
    if (inputBuffer.length !== 128) throw new Error('Solver input must be exactly 128 bytes');

    const view         = new DataView(inputBuffer.buffer, inputBuffer.byteOffset, 128);
    const startCounter = view.getUint32(124, /*littleEndian=*/true);
    // endCounter may exceed 32-bit range; that is intentional — setUint32 will
    // naturally truncate the written value to 32 bits, so the nonce wraps around.
    const endCounter   = startCounter + maxIterations;

    for (let counter = startCounter; counter < endCounter; counter++) {
      view.setUint32(124, counter, /*littleEndian=*/true);
      blake2bInitWithInput(state, inputBuffer);
      blake2bCompress(state, /*isFinalBlock=*/true);
      if (state.hashWords[0] < threshold) {
        return [inputBuffer, new Uint8Array(state.hashWords.buffer)];
      }
    }

    return [inputBuffer, new Uint8Array(0)]; // no solution found in this range
  };
}

/**
 * Creates a WebAssembly-accelerated Blake2b solver function.
 *
 * @param {Uint8Array|Buffer} wasmBytes - compiled WASM binary
 * @returns {Promise<Function>} (inputBuffer, threshold, maxIterations?) => [inputBuffer, hashBytes]
 */
async function createWasmSolver(wasmBytes) {
  const importObject = {
    env: { abort() { throw new Error('WASM computation aborted'); } }
  };

  const { instance } = await WebAssembly.instantiate(wasmBytes, importObject);
  const exports = wrapAssemblyScriptExports(instance.exports);

  // Pre-allocate and retain a 128-byte input buffer inside WASM memory
  const inputArrayRef  = exports.__retain(
    exports.__allocArray(exports.Uint8Array_ID, new Uint8Array(128))
  );
  let inputView = exports.__getUint8Array(inputArrayRef);

  return function wasmSolve(inputBuffer, threshold, maxIterations = 0xFFFFFFFF) {
    inputView.set(inputBuffer);
    const resultRef = exports.solveBlake2b(inputArrayRef, threshold, maxIterations);
    // Refresh input view in case WASM memory was grown by the runtime
    inputView = exports.__getUint8Array(inputArrayRef);
    const resultView = exports.__getUint8Array(resultRef);
    exports.__release(resultRef);
    return [inputView, resultView];
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Puzzle Parsing  (compatible with friendly-challenge v0.9.12)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Byte offsets within the 32-byte decoded puzzle buffer.
 * Matches the constants in the friendly-challenge v0.9.12 widget source.
 */
const PUZZLE_EXPIRY_OFFSET     = 13;
const PUZZLE_NUM_PUZZLES_OFFSET = 14;
const PUZZLE_DIFFICULTY_OFFSET  = 15;

/** Size of the 128-byte solver input block. */
const SOLVER_INPUT_SIZE = 128;

/** Byte index within solverInput where the puzzle index lives. */
const PUZZLE_INDEX_BYTE = 120;

/** Byte index within solverInput for the outer nonce counter (0–255). */
const OUTER_NONCE_BYTE = 123;

/** Byte offset within solverInput for the inner uint32 counter (LE). */
const INNER_NONCE_OFFSET = 124;

/**
 * Converts a FriendlyCaptcha difficulty byte (0–255) to a uint32 threshold.
 * Matches `difficultyToThreshold()` in friendly-challenge v0.9.12 exactly:
 *   difficulty 0   → ~99.99% solved on first attempt (very easy)
 *   difficulty 150 → ~4096 hashes on average
 *   difficulty 250+ → ~2^32 hashes on average (very hard)
 *
 * @param {number} difficultyByte - value 0–255 from puzzle buffer[15]
 * @returns {number} uint32 threshold — a hash is a solution when hash[0:4] < threshold
 */
function difficultyToThreshold(difficultyByte) {
  const clamped = Math.max(0, Math.min(255, difficultyByte));
  return Math.pow(2, (255.999 - clamped) / 8.0) >>> 0;
}

/**
 * Parses a FriendlyCaptcha puzzle string into the parameters needed by the solver.
 *
 * Puzzle string format: "<signature>.<puzzleBase64>"
 *   signature     — hex string (e.g. 32 hex chars = 16 bytes); identifies the account key
 *   puzzleBase64  — base64-encoded 32-byte puzzle data
 *
 * Solver input layout (128 bytes total, per puzzle index):
 *   bytes   0–31  : puzzle data (decoded from base64 part)
 *   bytes  32–119 : zero-padded nonce space
 *   byte   120    : puzzle index (0-based, one per sub-puzzle)
 *   bytes 121–122 : zeros
 *   byte   123    : outer nonce counter (0–255, iterated in the outer solve loop)
 *   bytes 124–127 : inner nonce counter (uint32 LE, iterated inside the hash loop)
 *
 * Puzzle header fields (offsets into the 32-byte puzzle buffer):
 *   puzzleBuffer[13] → expiry coefficient (expiry = value × 300 seconds)
 *   puzzleBuffer[14] → number of sub-puzzles to solve
 *   puzzleBuffer[15] → difficulty byte (used to compute the hash threshold)
 *
 * @param {string} puzzleString
 * @returns {{ signature: string, puzzleBase64: string, baseSolverInput: Uint8Array,
 *             threshold: number, numPuzzles: number, expiryMs: number }}
 */
function parsePuzzle(puzzleString) {
  const dotIndex = puzzleString.indexOf('.');
  if (dotIndex === -1) throw new Error('Invalid puzzle string: missing "." separator');

  const signature    = puzzleString.slice(0, dotIndex);
  const puzzleBase64 = puzzleString.slice(dotIndex + 1);

  const puzzleBuffer = Buffer.from(puzzleBase64, 'base64');

  const numPuzzles    = puzzleBuffer[PUZZLE_NUM_PUZZLES_OFFSET];
  const difficultyByte = puzzleBuffer[PUZZLE_DIFFICULTY_OFFSET];
  const expiryMs      = puzzleBuffer[PUZZLE_EXPIRY_OFFSET] * 300_000;
  const threshold     = difficultyToThreshold(difficultyByte);

  // Build the base 128-byte solver input: puzzle buffer at bytes 0–31, rest zeros.
  // Each sub-puzzle gets its own copy with byte 120 set to the puzzle index.
  const baseSolverInput = new Uint8Array(SOLVER_INPUT_SIZE);
  baseSolverInput.set(puzzleBuffer, 0);

  return { signature, puzzleBase64, baseSolverInput, threshold, numPuzzles, expiryMs };
}

// ─────────────────────────────────────────────────────────────────────────────
// Solution Token Builder
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Solver type IDs used in the diagnostics buffer.
 * Matches the `solverType` values in friendly-challenge v0.9.12.
 */
const SOLVER_ID_JS   = 1;
const SOLVER_ID_WASM = 2;

/**
 * Builds the 3-byte diagnostics buffer included in the solution token.
 * Matches `createDiagnosticsBuffer(solverID, timeToSolved)` in the widget.
 *
 * @param {number} solverID     - SOLVER_ID_JS or SOLVER_ID_WASM
 * @param {number} totalSeconds - time taken to solve all puzzles (seconds, rounded to uint16)
 * @returns {Uint8Array} 3-byte diagnostics buffer
 */
function buildDiagnosticsBuffer(solverID, totalSeconds) {
  const buf  = new Uint8Array(3);
  const view = new DataView(buf.buffer);
  view.setUint8(0, solverID);
  view.setUint16(1, Math.min(Math.round(totalSeconds), 0xFFFF)); // clamped to uint16 range
  return buf;
}

/**
 * Assembles the final `frc-captcha-solution` token string.
 *
 * Token format (compatible with friendly-challenge v0.9.12):
 *   "<signature>.<puzzleBase64>.<solutionBase64>.<diagnosticsBase64>"
 *
 * @param {string}     signature      - hex signature from the puzzle string
 * @param {string}     puzzleBase64   - base64 puzzle data (second part of puzzle string)
 * @param {Uint8Array} solutionBuffer - numPuzzles × 8 bytes (one 8-byte nonce per sub-puzzle)
 * @param {Uint8Array} diagnostics    - 3-byte diagnostics buffer
 * @returns {string} the frc-captcha-solution token
 */
function buildSolutionToken(signature, puzzleBase64, solutionBuffer, diagnostics) {
  const solutionBase64   = Buffer.from(solutionBuffer).toString('base64');
  const diagnosticsBase64 = Buffer.from(diagnostics).toString('base64');
  return `${signature}.${puzzleBase64}.${solutionBase64}.${diagnosticsBase64}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Worker Thread — Blake2b proof-of-work computation
// ─────────────────────────────────────────────────────────────────────────────

if (!isMainThread) {
  /**
   * Initialises the best available solver (WASM first, then JS) and posts a
   * 'ready' message to the parent thread.
   * @returns {Promise<{ solver: Function, solverID: number }>}
   */
  async function initSolver() {
    try {
      const wasmPath  = path.join(__dirname, 'wasm', 'solver.wasm');
      const wasmBytes = fs.readFileSync(wasmPath);
      const solver    = await createWasmSolver(wasmBytes);
      parentPort.postMessage({ type: 'ready', solverEngine: 'wasm' });
      return { solver, solverID: SOLVER_ID_WASM };
    } catch (wasmError) {
      process.stderr.write(
        `[cap] WASM solver unavailable, using JS fallback: ${wasmError.message}\n`
      );
      const solver = createJsSolver();
      parentPort.postMessage({ type: 'ready', solverEngine: 'js' });
      return { solver, solverID: SOLVER_ID_JS };
    }
  }

  const solverInitPromise = initSolver();

  parentPort.on('message', async (msg) => {
    if (msg.type !== 'solve') return;

    try {
      const { solver, solverID } = await solverInitPromise;
      const { solverInput, threshold, puzzleIndex, numPuzzles } = msg;

      let solvedInput    = null;
      let totalHashCount = 0;

      // Outer loop: iterate byte 123 (0–255) as an additional nonce dimension.
      // Matches the outer loop in the original WebWorker cap.js.
      for (let outerNonce = 0; outerNonce < 256; outerNonce++) {
        solverInput[OUTER_NONCE_BYTE] = outerNonce;
        const [updatedInput, hashBytes] = solver(solverInput, threshold);

        if (hashBytes.length > 0) {
          solvedInput = updatedInput;
          break;
        }

        // Accumulate work: this pass exhausted ~2^32 counter values (0xFFFFFFFF = 2^32 - 1)
        totalHashCount += 0xFFFFFFFF;
      }

      if (solvedInput === null) {
        parentPort.postMessage({
          type: 'error',
          message: `No solution found after 256 × 2^32 iterations (puzzle ${puzzleIndex})`
        });
        return;
      }

      // Add the final inner-counter value to get total hashes computed.
      // Matches: g += new DataView(I.slice(-4).buffer).getUint32(0, true)
      const finalCounterView = new DataView(
        solvedInput.buffer, solvedInput.byteOffset + INNER_NONCE_OFFSET, 4
      );
      totalHashCount += finalCounterView.getUint32(0, /*littleEndian=*/true);

      // The solution nonce is bytes 120–127 of the solved input:
      //   byte 120: puzzle index
      //   bytes 121–122: zeros
      //   byte 123: outer nonce that succeeded
      //   bytes 124–127: inner counter value that produced hash < threshold
      // This matches `solution: I.slice(-8)` in the original WebWorker.
      const solutionSegment = Buffer.from(solvedInput.slice(PUZZLE_INDEX_BYTE, SOLVER_INPUT_SIZE));

      parentPort.postMessage({
        type: 'done',
        solutionSegment,      // 8-byte Buffer (bytes 120–127 of the solved input)
        solverID,             // SOLVER_ID_JS or SOLVER_ID_WASM
        totalHashCount,       // total Blake2b hashes computed
        puzzleIndex,          // which sub-puzzle this solves (0-based)
        numPuzzles            // total number of sub-puzzles in this challenge
      });
    } catch (err) {
      parentPort.postMessage({ type: 'error', message: err.message });
    }
  });

  parentPort.on('error', (err) => {
    process.stderr.write(`[cap] Worker port error: ${err.message}\n`);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Thread — coordination, puzzle fetching, result reporting
// ─────────────────────────────────────────────────────────────────────────────

if (isMainThread) {
  /**
   * Fetches a puzzle from the FriendlyCaptcha API.
   *
   * @param {string} siteKey - the FriendlyCaptcha site key
   * @returns {Promise<string>} the raw puzzle string (e.g. "abc123.base64data==")
   */
  function fetchPuzzle(siteKey) {
    return new Promise((resolve, reject) => {
      const url = `https://api.friendlycaptcha.com/api/v1/puzzle?sitekey=${encodeURIComponent(siteKey)}`;
      https.get(url, (res) => {
        let rawBody = '';
        res.on('data', (chunk) => { rawBody += chunk; });
        res.on('end', () => {
          try {
            const json = JSON.parse(rawBody);
            if (!json.success || !json.data || !json.data.puzzle) {
              reject(new Error(`API error: ${rawBody}`));
            } else {
              resolve(json.data.puzzle);
            }
          } catch (e) {
            reject(new Error(`Failed to parse API response: ${e.message}`));
          }
        });
      });
      req.on('error', reject);
    });
  }

  /**
   * Spawns a Worker Thread to solve one sub-puzzle.
   *
   * @param {Uint8Array} baseSolverInput - 128-byte solver input (puzzle buffer at 0–31)
   * @param {number}     threshold       - hash threshold
   * @param {number}     puzzleIndex     - sub-puzzle index (0-based)
   * @param {number}     numPuzzles      - total sub-puzzles in the challenge
   * @returns {Promise<Object>} the 'done' message from the worker
   */
  function runWorkerSolver(baseSolverInput, threshold, puzzleIndex, numPuzzles) {
    return new Promise((resolve, reject) => {
      // Each worker gets its own copy of the solver input so they can modify
      // it independently (outer/inner nonce bytes) without interfering.
      const solverInput = new Uint8Array(baseSolverInput);
      solverInput[PUZZLE_INDEX_BYTE] = puzzleIndex; // byte 120 = puzzle index

      const worker = new Worker(__filename);

      worker.once('error', (err) => {
        reject(err);
        worker.terminate();
      });

      worker.on('message', (msg) => {
        switch (msg.type) {
          case 'ready':
            // Worker has initialised its solver; send the solve request
            worker.postMessage({ type: 'solve', solverInput, threshold, puzzleIndex, numPuzzles });
            break;
          case 'done':
            resolve(msg);
            worker.terminate();
            break;
          case 'error':
            reject(new Error(msg.message));
            worker.terminate();
            break;
        }
      });
    });
  }

  /**
   * Solves a raw puzzle string and returns the `frc-captcha-solution` token.
   *
   * All sub-puzzles are solved concurrently (one Worker Thread each).
   *
   * @param {string} puzzleString - the raw puzzle string from the API
   * @returns {Promise<string>} the frc-captcha-solution token ready for form submission
   */
  async function solvePuzzleString(puzzleString) {
    const { signature, puzzleBase64, baseSolverInput, threshold, numPuzzles } =
      parsePuzzle(puzzleString);

    const startTime = Date.now();

    // Solve all sub-puzzles concurrently, one worker per sub-puzzle
    const workerResults = await Promise.all(
      Array.from({ length: numPuzzles }, (_, i) =>
        runWorkerSolver(baseSolverInput, threshold, i, numPuzzles)
      )
    );

    const totalSeconds = (Date.now() - startTime) / 1000;

    // Assemble the solution buffer: 8 bytes per sub-puzzle in index order
    const solutionBuffer = new Uint8Array(numPuzzles * 8);
    let   totalHashCount = 0;
    let   solverID       = SOLVER_ID_WASM; // downgrade to JS if any worker used JS

    for (const result of workerResults) {
      solutionBuffer.set(result.solutionSegment, result.puzzleIndex * 8);
      totalHashCount += result.totalHashCount;
      if (result.solverID === SOLVER_ID_JS) solverID = SOLVER_ID_JS;
    }

    const diagnostics = buildDiagnosticsBuffer(solverID, totalSeconds);
    const token       = buildSolutionToken(signature, puzzleBase64, solutionBuffer, diagnostics);

    return token;
  }

  /**
   * Fetches a puzzle from the API and solves it, returning the frc-captcha-solution token.
   *
   * @param {string} siteKey - the FriendlyCaptcha site key
   * @returns {Promise<string>} the frc-captcha-solution token
   */
  async function fetchAndSolvePuzzle(siteKey) {
    const puzzleString = await fetchPuzzle(siteKey);
    console.log(`[cap] Fetched puzzle: ${puzzleString}`);
    return solvePuzzleString(puzzleString);
  }

  // ── Module export ──────────────────────────────────────────────────────────
  module.exports = {
    fetchAndSolvePuzzle,
    solvePuzzleString,
    fetchPuzzle,
    parsePuzzle,
    buildSolutionToken,
    difficultyToThreshold
  };

  // ── CLI entry point ────────────────────────────────────────────────────────
  if (require.main === module) {
    const EXAMPLE_SITE_KEY = 'FCMSPLFFSPQ6TH80';
    const siteKey = process.argv[2] || EXAMPLE_SITE_KEY;

    console.log(`[cap] Solving FriendlyCaptcha puzzle for sitekey: ${siteKey}`);

    fetchAndSolvePuzzle(siteKey)
      .then((token) => {
        console.log('[cap] frc-captcha-solution token:');
        console.log(token);
        process.exit(0);
      })
      .catch((err) => {
        console.error('[cap] Error:', err.message);
        process.exit(1);
      });
  }
}
