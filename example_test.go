package c2pa_test

import (
	"context"
	"fmt"
	"os"

	"github.com/richardwooding/c2pa"
)

// Example reads the Content Credentials a JPEG claims, and surfaces the
// (unverified) creating tool, AI-generated flag, and signer identity.
func Example() {
	f, err := os.Open("testdata/c2pa_signed.jpg")
	if err != nil {
		panic(err)
	}
	defer func() { _ = f.Close() }()

	info := c2pa.Read(context.Background(), c2pa.JPEG, f)
	if !info.Present {
		fmt.Println("no Content Credentials")
		return
	}
	fmt.Println("title:", info.Title)
	fmt.Println("ai-generated:", info.AIGenerated)
	// SignedBy is the CLAIMED signer — not cryptographically verified.
	fmt.Println("signed by:", info.SignedBy)
	// Output:
	// title: CA.jpg
	// ai-generated: false
	// signed by: C2PA Signer
}

// ExampleValidate verifies a JPEG's Content Credentials against the embedded
// C2PA trust list. The test fixture is signed by the c2pa-rs *test* PKI, so its
// signature verifies cryptographically but its signer does not chain to a
// production trust anchor — an honest "valid signature, untrusted signer"
// verdict. Pass WithSigningTrust / WithTimestampTrust to supply your own anchors.
func ExampleValidate() {
	f, err := os.Open("testdata/c2pa_signed.jpg")
	if err != nil {
		panic(err)
	}
	defer func() { _ = f.Close() }()

	r := c2pa.Validate(context.Background(), c2pa.JPEG, f)
	fmt.Println("valid:", r.Valid)
	fmt.Println("signature verified:", r.Has(c2pa.StatusClaimSignatureValidated))
	fmt.Println("signer trusted:", r.Has(c2pa.StatusSigningCredentialTrusted))
	// Output:
	// valid: false
	// signature verified: true
	// signer trusted: false
}
