# c2pa

[![Go Reference](https://pkg.go.dev/badge/github.com/richardwooding/c2pa.svg)](https://pkg.go.dev/github.com/richardwooding/c2pa)
[![CI](https://github.com/richardwooding/c2pa/actions/workflows/ci.yml/badge.svg)](https://github.com/richardwooding/c2pa/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/richardwooding/c2pa)](https://goreportcard.com/report/github.com/richardwooding/c2pa)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A small, **pure-Go, read-only** reader for [C2PA / Content Credentials](https://c2pa.org)
provenance manifests embedded in **JPEG** and **PNG** files.

It surfaces what a file *claims* about its provenance — the creating tool, title, declared
format, whether it declares AI-generated content, and the signer identity + signing time — by
parsing the embedded JUMBF manifest (ISO 19566-5), CBOR-decoding the active manifest's claim and
`c2pa.actions` assertion, and decoding the COSE_Sign1 signature envelope.

```sh
go get github.com/richardwooding/c2pa
```

## ⚠️ This is UNVERIFIED — read, not validate

This library is the equivalent of reading EXIF, or an email `From:` header: it reports the file's
**claims**, it does **not** authenticate them.

- It does **not** verify the COSE cryptographic signature.
- It does **not** check the signer's certificate chain against the [C2PA trust list](https://opensource.contentauthenticity.org/docs/verify/#trust-lists).
- `SignedBy` is *who the file claims signed it*, not a verified identity.

Full validation requires the Rust [`c2pa-rs`](https://github.com/contentauth/c2pa-rs) library via
CGO. This package intentionally stays pure-Go and read-only — useful for **search, indexing,
triage, and inventory** ("find images with Content Credentials", "find AI-generated assets", "who
does this file claim signed it"), not for trust decisions.

## Usage

```go
f, _ := os.Open("photo.jpg")
defer f.Close()

info := c2pa.Read(context.Background(), c2pa.JPEG, f) // or c2pa.PNG
if !info.Present {
    // no Content Credentials embedded
    return
}

fmt.Println(info.ClaimGenerator) // e.g. "Adobe Firefly"
fmt.Println(info.Title)          // claim dc:title
fmt.Println(info.Format)         // claim dc:format
fmt.Println(info.AIGenerated)    // declared AI-generated?
fmt.Println(info.SignedBy)       // CLAIMED signer cert CN (unverified)
fmt.Println(info.SignedAt)       // RFC 3161 signing time (unverified)
```

`Read` is best-effort and never returns an error: a missing or malformed manifest yields
`Info{Present: false}`. It reads at most `c2pa.MaxScan` (16 MiB) from the reader and honours the
context — a cancelled call surrenders promptly mid-scan.

### `Info`

| Field | Meaning |
|---|---|
| `Present` | a C2PA manifest was found and parsed |
| `ClaimGenerator` | the tool that created/edited the asset |
| `Title` | claim `dc:title` |
| `Format` | claim `dc:format` (declared media type) |
| `AIGenerated` | a `c2pa.actions` `digitalSourceType` declares `trainedAlgorithmicMedia` / `compositeWithTrainedAlgorithmicMedia` |
| `SignedBy` | COSE signer leaf-cert common name — **unverified** |
| `SignedAt` | RFC 3161 signing time — **unverified** |

### Lower-level

`c2pa.WalkBoxes(ctx, jumbf, fn)` exposes the JUMBF box-tree walker for callers that want to surface
assertions `Read` doesn't model. Box nesting is depth-capped so adversarial input can't exhaust the
stack.

## Requirements

- **Go 1.23+**
- Depends on [`fxamacker/cbor`](https://github.com/fxamacker/cbor) (CBOR) and
  [`veraison/go-cose`](https://github.com/veraison/go-cose) (COSE_Sign1) — both pure-Go.

## License

MIT — see [LICENSE](LICENSE). The test fixture under `testdata/` is from
[contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs) (see `testdata/README.md`).

---

Extracted from [file-search-on](https://github.com/richardwooding/file-search-on), where it powers
the `is_c2pa` / `c2pa_*` search attributes.
