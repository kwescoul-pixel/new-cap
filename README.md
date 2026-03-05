# FriendlyCaptcha Puzzle Solver (Node.js)

Solves FriendlyCaptcha proof-of-work puzzles using Blake2b-256 hashing.
Compatible with **friendly-challenge v0.9.12** — produces the same `frc-captcha-solution`
token as the browser widget.

Uses WebAssembly for speed, with a pure-JavaScript fallback.
The heavy computation runs in a Node.js **Worker Thread** to keep the main thread non-blocking.

## Files

| File | Purpose |
|------|---------|
| `cap.js` | Main entry point — puzzle parsing, worker coordination, API fetching, token building |
| `html.html` | FriendlyCaptcha widget demo page — shows the widget and the solution token |
| `wasm/solver.wasm` | Compiled WebAssembly Blake2b solver |
| `wasm/kk.txt` | WebAssembly Text (WAT) source for the WASM solver |

## Usage

### CLI

```bash
# Fetch a fresh puzzle from the API and solve it
node cap.js

# Solve using a specific site key
node cap.js YOUR_SITE_KEY
```

Output:
```
[cap] Fetched puzzle: f7b1be5e7a798d860fe7be671602e833.aanq...
[cap] frc-captcha-solution token:
f7b1be5e7a798d860fe7be671602e833.aanq....AAAAAE8mAAA=.AgAA
```

### Module API

```js
const { fetchAndSolvePuzzle, solvePuzzleString } = require('./cap');

// Fetch from the API and solve (returns the token string directly)
const token = await fetchAndSolvePuzzle('FCMSPLFFSPQ6TH80');
console.log(token);
// → "f7b1be5e…833.aanq….AAAAAE8mAAA=.AgAA"

// Solve an existing puzzle string
const token2 = await solvePuzzleString('f7b1be5e…833.aanqoczV7+Z0bsU…=');

// Submit token in a form POST
await fetch('https://example.com/login', {
  method: 'POST',
  body: new URLSearchParams({
    username: 'alice',
    password: 'secret',
    'frc-captcha-solution': token,
  }),
});
```

### Browser widget (html.html)

Open `html.html` in a browser to see the FriendlyCaptcha widget in action.
After the puzzle is solved the token is displayed on-page for inspection.

## frc-captcha-solution Token Format

The token is a dot-separated string with **four parts**:

```
<signature>.<puzzleBase64>.<solutionBase64>.<diagnosticsBase64>
```

| Part | Description |
|------|-------------|
| `signature` | Hex string identifying the account/sitekey (from the API response) |
| `puzzleBase64` | Base64-encoded 32-byte puzzle data (from the API response) |
| `solutionBase64` | Base64 of 8 bytes × numPuzzles — the nonce(s) that satisfy `hash[0:4] < threshold` |
| `diagnosticsBase64` | Base64 of 3 bytes: `[solverID, timeSeconds_hi, timeSeconds_lo]` |

`solverID`: 1 = JavaScript, 2 = WebAssembly

### Puzzle data layout (32-byte buffer from `puzzleBase64`)

| Offset | Field | Description |
|--------|-------|-------------|
| 13 | expiry | `value × 300 000 ms` (e.g. 12 → 1 hour) |
| 14 | numPuzzles | number of sub-puzzles to solve |
| 15 | difficulty | threshold = `Math.pow(2, (255.999 − byte) / 8.0) \|>> 0` |

### Solver input layout (128 bytes per sub-puzzle)

| Bytes | Content |
|-------|---------|
| 0–31 | puzzle buffer (decoded from `puzzleBase64`) |
| 32–119 | zeros |
| 120 | puzzle index (0-based) |
| 121–122 | zeros |
| 123 | outer nonce counter (0–255) |
| 124–127 | inner nonce counter (uint32 LE) |

## Architecture

```
Main Thread                          Worker Thread (one per sub-puzzle)
────────────────────                 ────────────────────────────────
fetchPuzzle(siteKey)                 initSolver()
  └─ HTTPS GET /api/v1/puzzle          └─ load wasm/solver.wasm (or JS fallback)
                                        └─ post { type:'ready' }
parsePuzzle(puzzleString)
  └─ baseSolverInput (128 bytes)
  └─ threshold
  └─ numPuzzles

runWorkerSolver(...)  ──────────────────────────────────────────►
  receive 'ready'      post { type:'solve', solverInput, threshold, puzzleIndex }
                                       ◄──────────────────────────────────────
                         for outerNonce in 0..255:
                           solverInput[123] = outerNonce
                           loop inner counter (bytes 124-127) via Blake2b
                           if hash[0:4] < threshold → found!
                         post { type:'done', solutionNonceBytes[8], ... }
collect results        ◄──────────────────────────────────────────

buildSolutionToken(
  signature, puzzleBase64,
  solutionBuffer,   ← concat 8-byte nonces for each sub-puzzle
  diagnostics       ← 3 bytes
) → "signature.puzzleBase64.solutionBase64.diagnosticsBase64"
```
