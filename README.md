# FriendlyCaptcha Puzzle Solver (Node.js)

Solves FriendlyCaptcha proof-of-work puzzles using Blake2b-256 hashing.
Uses WebAssembly for speed, with a pure-JavaScript fallback.
The heavy computation runs in a Node.js **Worker Thread** to keep the main thread non-blocking.

## Files

| File | Purpose |
|------|---------|
| `cap.js` | Main entry point — puzzle parsing, worker coordination, API fetching |
| `wasm/solver.wasm` | Compiled WebAssembly Blake2b solver |
| `wasm/kk.txt` | WebAssembly Text (WAT) source for the WASM solver |

## Usage

### CLI

```bash
# Solve a puzzle for the default site key
node cap.js

# Solve a puzzle for a specific site key
node cap.js YOUR_SITE_KEY
```

### Module API

```js
const { fetchAndSolvePuzzle, solvePuzzleString } = require('./cap');

// Fetch from the API and solve
const results = await fetchAndSolvePuzzle('FCMSPLFFSPQ6TH80');
console.log(results[0].solutionNonce); // base64 nonce

// Solve an existing puzzle string
const results = await solvePuzzleString('abc123.puzzleDataBase64==');
```

## Puzzle Format

A FriendlyCaptcha puzzle string looks like:
```
f7b1be5e7a798d860fe7be671602e833.aanqoczV7+Z0bsUAAQwzywAAAAAAAAAAd78gt2ZTOws=
```

- **Part 1 (hex):** 16-byte account key (sitekey-derived identifier)
- **Part 2 (base64):** 32-byte puzzle data containing expiry, difficulty, and challenge bytes

The solver constructs a 128-byte input (`accountKey + puzzleData + nonce`), then
searches for a nonce such that `blake2b256(input)[0:4] < threshold`.

## Architecture

```
Main Thread                          Worker Thread
────────────────────                 ────────────────────────────────
fetchPuzzle(siteKey)                 initSolver()
  └─ HTTPS GET /api/v1/puzzle          └─ load wasm/solver.wasm  (or JS fallback)
                                        └─ post { type:'ready' }
parsePuzzle(puzzleString)
  └─ solverInput (128 bytes)
  └─ threshold
  └─ numPuzzles

runWorkerSolver(...)  ───────────────────────────────────►
  receive 'ready'     post { type:'solve', solverInput, threshold, ... }
                                       ◄────────────────────
                      for outerNonce in 0..255:
                        solverInput[123] = outerNonce
                        loop inner counter (bytes 124-127) via Blake2b
                        if hash[0] < threshold → found!
                      post { type:'done', solutionNonce, totalHashCount }
resolve(result)       ◄──────────────────────────────────
```
