Replace PGP word lists with EFF Short Wordlist 1 for SAS generation. No backward compatibility — clean removal of all legacy code.

## Changes

### `internal/crypto/crypto.go`

- **Delete** `pgpWordListEven`, `pgpWordListOdd` (256 entries each, ~150 lines)
- **Rewrite** `SASFromBytes` to draw words from `effShortWordlist` (1,296 entries, already exists in file)
- Word count: 8 → 6 (keeps ~62 bits of output entropy, close to current ~64)
- Use the same rejection-sampling approach as `randomWordIndex` but sourced from key material bytes instead of `crypto/rand` — produces deterministic output for a given key material input, no bias (fixes SUM-08)
- Remove double-modulo bias (`% 256` then `% len(list)`)
- Delete `SASString` if it becomes trivial or unused; inline if only one caller

### `internal/crypto/crypto_test.go`

- Update `TestSASFromBytes` expectations: 6 words instead of 8, from EFF list
- Add a test that the same key material always produces the same SAS (determinism)
- Add a test that different key material produces different output

### `internal/cli/tx.go`

- Update `promptSASVerificationFrom` if word count or format changes the printed line
- Verify the SAS output line length fits in one terminal line

### `internal/server/server_ws_test.go` (if it references SAS word count or word lists)

- Update any hardcoded SAS expectations

## Cleanup checklist

- [x] No references to `pgpWordListEven` or `pgpWordListOdd` remain anywhere in the codebase
- [x] SAS output is 6 words from EFF Short Wordlist 1
- [x] SAS output is deterministic from key material (no `crypto/rand` in the SAS path)
- [x] No modulo bias in word selection
- [x] All tests pass: `go test ./...`
- [x] E2E tests pass: `go test ./e2e/...`
- [x] Coverage stays >=80% for all affected packages
