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
