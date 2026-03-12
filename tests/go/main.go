// This program generates KSUID test vectors using the Go reference implementation
// (segmentio/ksuid) and outputs them as JSON. The Rust integration test reads this
// JSON and validates that our implementation produces identical results.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/segmentio/ksuid"
)

type TestVector struct {
	Description string `json:"description"`
	Timestamp   uint32 `json:"timestamp"`
	PayloadHex  string `json:"payload_hex"`
	RawHex      string `json:"raw_hex"`
	String      string `json:"string"`
	NextString  string `json:"next_string"`
	PrevString  string `json:"prev_string"`
}

func makeKSUID(timestamp uint32, payloadHex string) ksuid.KSUID {
	payload, err := hex.DecodeString(payloadHex)
	if err != nil {
		panic(err)
	}
	var id ksuid.KSUID
	// Timestamp bytes (big-endian)
	id[0] = byte(timestamp >> 24)
	id[1] = byte(timestamp >> 16)
	id[2] = byte(timestamp >> 8)
	id[3] = byte(timestamp)
	copy(id[4:], payload)
	return id
}

func main() {
	testCases := []struct {
		description string
		timestamp   uint32
		payloadHex  string
	}{
		{"nil", 0, "00000000000000000000000000000000"},
		{"max", 4294967295, "ffffffffffffffffffffffffffffffff"},
		{"standard", 95004740, "669f7efd7b6fe812278486085878563d"},
		{"zero_payload", 95004740, "00000000000000000000000000000000"},
		{"max_payload", 95004740, "ffffffffffffffffffffffffffffffff"},
		{"epoch_with_pattern", 0, "0123456789abcdef0123456789abcdef"},
		{"max_int32_deadbeef", 2147483647, "deadbeefdeadbeefdeadbeefdeadbeef"},
		{"zero_ts_deadbeef", 0, "deadbeefdeadbeefdeadbeefdeadbeef"},
		{"max_ts_pattern", 4294967295, "abcdef0123456789abcdef0123456789"},
		{"mid_range", 1000000, "aabbccdd11223344aabbccdd11223344"},
		{"one_ts", 1, "00000000000000000000000000000001"},
		{"alternating", 2863311530, "55555555555555555555555555555555"},
	}

	vectors := make([]TestVector, 0, len(testCases))

	for _, tc := range testCases {
		id := makeKSUID(tc.timestamp, tc.payloadHex)
		next := id.Next()
		prev := id.Prev()

		vectors = append(vectors, TestVector{
			Description: tc.description,
			Timestamp:   tc.timestamp,
			PayloadHex:  tc.payloadHex,
			RawHex:      hex.EncodeToString(id[:]),
			String:      id.String(),
			NextString:  next.String(),
			PrevString:  prev.String(),
		})
	}

	// Also verify Nil and Max constants match
	nilVec := TestVector{
		Description: "go_nil_constant",
		Timestamp:   0,
		PayloadHex:  "00000000000000000000000000000000",
		RawHex:      hex.EncodeToString(ksuid.Nil[:]),
		String:      ksuid.Nil.String(),
		NextString:  ksuid.Nil.Next().String(),
		PrevString:  ksuid.Nil.Prev().String(),
	}

	maxVec := TestVector{
		Description: "go_max_constant",
		Timestamp:   4294967295,
		PayloadHex:  "ffffffffffffffffffffffffffffffff",
		RawHex:      hex.EncodeToString(ksuid.Max[:]),
		String:      ksuid.Max.String(),
		NextString:  ksuid.Max.Next().String(),
		PrevString:  ksuid.Max.Prev().String(),
	}

	vectors = append(vectors, nilVec, maxVec)

	// Generate 10 random KSUIDs and record their encode/decode roundtrip
	for i := 0; i < 10; i++ {
		id := ksuid.New()
		vectors = append(vectors, TestVector{
			Description: fmt.Sprintf("random_%d", i),
			Timestamp:   uint32(id[0])<<24 | uint32(id[1])<<16 | uint32(id[2])<<8 | uint32(id[3]),
			PayloadHex:  hex.EncodeToString(id[4:]),
			RawHex:      hex.EncodeToString(id[:]),
			String:      id.String(),
			NextString:  id.Next().String(),
			PrevString:  id.Prev().String(),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vectors); err != nil {
		fmt.Fprintf(os.Stderr, "error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}
