# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`github.com/richardwooding/c2pa` is a tiny, flat (single-package, no subpackages) **pure-Go,
read-only** reader for C2PA / Content Credentials provenance manifests in JPEG and PNG. The entire
implementation is `c2pa.go`. The public surface is small:

- `Read(ctx, container, r) Info` — the entry point. `container` is `JPEG` or `PNG`.
- `Info` — the surfaced fields (Present, ClaimGenerator, Title, Format, AIGenerated, SignedBy, SignedAt).
- `WalkBoxes(ctx, jumbf, fn)` — lower-level JUMBF box-tree walker.
- `MaxScan` — the 16 MiB read cap.

## Commands

```sh
go test ./...                                  # all tests + fuzz seed corpus
go test -run TestRead_SignedJPEG               # single test by name
go test -race -timeout 120s ./...              # what CI runs
go test -run='^$' -fuzz=FuzzWalkBoxes -fuzztime=30s   # mutate one fuzz target
go vet ./...
golangci-lint run
```

CI (`.github/workflows/ci.yml`) runs build + vet + race tests on Go `1.23` and `stable` plus
golangci-lint. `.github/workflows/fuzz.yml` mutates the three fuzz targets nightly.

## The non-goal is the whole point

This library **reads claims; it does not validate them.** It does NOT verify the COSE signature and
does NOT check the certificate chain against the C2PA trust list. That is a deliberate, permanent
design decision — full validation needs Rust `c2pa-rs` via CGO, which defeats the reason this exists
(a dependency-light, pure-Go reader for search/indexing/triage). Do not add "verification" that only
half-checks; either it's the honest unverified reader it claims to be, or it's a different project.
Every doc comment leans on this framing (EXIF / unverified From header) — keep it.

## Things to know before editing

- **Go 1.23 is the floor.** The code uses `reflect.TypeFor` (Go 1.22+). Don't raise the floor
  without updating both `go.mod` and the CI matrix's lower bound.
- **CBOR maps must decode to `map[string]any`.** `decMode` configures fxamacker/cbor with
  `DefaultMapType: map[string]any` — otherwise nested maps come back as `map[any]any` and every
  text-key lookup (`claim["dc:title"]`, etc.) silently misses. This was the original integration bug.
- **The x5chain header key is an `int64`.** go-cose keys protected/unprotected headers with its
  `cose.HeaderLabelX5Chain` constant, which is `int64(33)`. Looking it up with a bare `int(33)`
  literal misses the map entry and yields an empty `SignedBy`. Always use the constant.
- **AI detection is case-folded substring match.** `compositeWithTrainedAlgorithmicMedia` has a
  capital "T", so `isAIDigitalSourceType` lowercases before `strings.Contains(…, "trainedalgorithmicmedia")`.
  It checks both the action's top-level `digitalSourceType` and its `parameters`.
- **`maxJUMBFDepth` (64) caps recursion.** JUMBF `jumb` superboxes nest, and a chain of nested boxes
  (each stripping only an 8-byte header) could otherwise nest ~MaxScan/8 levels and blow the stack on
  adversarial input. Real manifests nest ~4 deep. Don't remove the cap.
- **Everything is best-effort and must never panic.** Malformed/truncated/cancelled input returns
  zero values. The RFC 3161 ASN.1 descent (`rfc3161GenTime`) is deliberately defensive at every
  `asn1.Unmarshal` step. This contract is enforced by the fuzz targets — keep them green.
- **`signedAt` lives in an RFC 3161 timestamp.** `sigTst` (COSE unprotected header) holds
  `tstTokens[].val`, each a `TimeStampResp` → CMS `SignedData` → `TSTInfo.genTime`. The walk handles
  both a full `TimeStampResp` and a bare `ContentInfo`.

## Tests

`testdata/c2pa_signed.jpg` is a real signed JPEG from contentauth/c2pa-rs (see `testdata/README.md`
for provenance + license). `TestActionsAreAI` synthesises CBOR assertions in-memory because there's
no public AI-positive fixture. `example_test.go` holds the runnable godoc `Example` — keep it passing,
it doubles as documentation. The three `Fuzz*` targets cover the full pipeline, the recursive box
walker, and the ASN.1 timestamp descent; their seed corpora run as normal tests in CI.
