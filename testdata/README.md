# testdata

## c2pa_signed.jpg

A real C2PA-signed JPEG used as the parser fixture. It is `CA.jpg` from the
[contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs) project's test
assets (`sdk/tests/fixtures/`), licensed under Apache-2.0 / MIT (the c2pa-rs
dual license).

It carries a manifest with claim_generator `make_test_images/0.33.1
c2pa-rs/0.33.1`, title `CA.jpg`, a COSE_Sign1 signature whose leaf certificate
subject CN is `C2PA Signer`, and an RFC 3161 timestamp of
`2024-08-06T21:53:37Z`. It is an *edited* image, not AI-generated.
