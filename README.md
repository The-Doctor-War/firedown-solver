# firedown-solver

Remote YouTube n-parameter solver for [Firedown](https://firedown.app) — a privacy-focused Android browser with built-in media downloading.

## What this does

YouTube throttles video streams by encrypting the `n` URL parameter. Without solving it, streams are rate-limited to unusable speeds. This solver decrypts the `n` parameter so Firedown can deliver full-speed HLS playback.

The solver runs inside Firedown's YouTube WebExtension. Instead of being bundled in the APK (which would require an app update every time YouTube changes their player), the solver is fetched from this repo at runtime and cached locally. When YouTube pushes a new player version, we update `solver.js` here and every Firedown user picks it up automatically — no app update needed.

## How it works

YouTube's player.js contains an obfuscated dispatch function that transforms the `n` parameter. The solver:

1. **Parses the string table** — YouTube players always have a string table (various formats: `.split(";")`, `.split("}")`, array literals) containing method names like `"split"`, `"join"`, `"length"`.

2. **Finds candidate dispatch functions** — Scans the first 30KB of the player for functions with 3+ parameters whose bodies contain XOR-indexed string table accesses (`TABLE[VAR^NUM]`).

3. **Generates test parameters** — For each candidate function and each XOR access, computes a possible `(r, p)` parameter pair using the known index of `"split"` in the string table.

4. **Behavioral probing** — Executes the player.js in a sandbox, saves references to candidate functions before they get overwritten, then probes each `(function, r, p)` combination with a test string. The correct combination transforms the input deterministically.

5. **Caches the result** — The working `(funcName, r, p)` tuple is cached in `browser.storage.local` so subsequent loads skip the solve entirely.

## Files

| File | Description |
|------|-------------|
| `solver.js` | The solver module fetched by Firedown at runtime |

## Updating

When YouTube changes their player obfuscation:

1. Update `solver.js` with the fix
2. Bump `SOLVER_VERSION` at the top of the file
3. Commit and push to `main`

Firedown checks for updates every 6 hours. Users get the fix automatically.

## Fallback chain

If the solver can't decrypt the `n` parameter (new player, network failure, etc.), Firedown falls through:

1. **Memory cache** — instant if already solved this session
2. **Storage cache** — cached `(funcName, r, p)` from previous solve
3. **Remote solver** — latest `solver.js` from this repo
4. **Bundled solver** — copy embedded in the APK
5. **ANDROID_VR API** — bypasses `n` parameter entirely via native Java/OkHttp

## Player versions tested

| Player | String table | Dispatch | Status |
|--------|-------------|----------|--------|
| `6c5cb4f4` (TV) | `"...".split(";")` | eF | ✅ |
| `44899b31` (TV) | `"...".split(";")` | fF | ✅ |
| `56211dc2` (TV) | `'...'.split("}")` | Gi | ✅ |
| `99f55c01` (TV) | `["...","..."]` | B1 | ✅ |

## License

MIT
