package ldap

import (
	"testing"
)

func TestBEREncodeLength(t *testing.T) {
	tests := []struct {
		input    int
		expected []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{256, []byte{0x82, 0x01, 0x00}},
		{65535, []byte{0x82, 0xff, 0xff}},
	}
	for _, tt := range tests {
		got := berEncodeLength(tt.input)
		if len(got) != len(tt.expected) {
			t.Errorf("berEncodeLength(%d) = %x, want %x", tt.input, got, tt.expected)
			continue
		}
		for i := range got {
			if got[i] != tt.expected[i] {
				t.Errorf("berEncodeLength(%d) = %x, want %x", tt.input, got, tt.expected)
				break
			}
		}
	}
}

func TestBERIntegerRoundTrip(t *testing.T) {
	tests := []int{0, 1, 127, 128, 255, 256, 65535, -1}
	for _, val := range tests {
		encoded := berInteger(val)
		elem, consumed, err := parseBERElement(encoded, 0)
		if err != nil {
			t.Errorf("berInteger(%d): parse error: %v", val, err)
			continue
		}
		if consumed != len(encoded) {
			t.Errorf("berInteger(%d): consumed %d, want %d", val, consumed, len(encoded))
		}
		if elem.Tag != berTagInteger {
			t.Errorf("berInteger(%d): tag 0x%02x, want 0x%02x", val, elem.Tag, berTagInteger)
		}
	}
}

func TestBEROctetStringRoundTrip(t *testing.T) {
	tests := [][]byte{
		nil,
		{},
		[]byte("hello"),
		make([]byte, 200), // triggers multi-byte length
	}
	for _, data := range tests {
		encoded := berOctetString(data)
		elem, consumed, err := parseBERElement(encoded, 0)
		if err != nil {
			t.Errorf("berOctetString(%q): parse error: %v", data, err)
			continue
		}
		if consumed != len(encoded) {
			t.Errorf("berOctetString(%q): consumed %d, want %d", data, consumed, len(encoded))
		}
		if elem.Tag != berTagOctetString {
			t.Errorf("berOctetString(%q): tag 0x%02x, want 0x%02x", data, elem.Tag, berTagOctetString)
		}
		if len(elem.Data) != len(data) {
			t.Errorf("berOctetString: data length %d, want %d", len(elem.Data), len(data))
		}
	}
}

func TestBERSequenceRoundTrip(t *testing.T) {
	inner := berInteger(42)
	seq := berSequence(inner, berOctetString([]byte("test")))
	elem, _, err := parseBERElement(seq, 0)
	if err != nil {
		t.Fatalf("parse sequence: %v", err)
	}
	if elem.Tag != berTagSequence {
		t.Errorf("tag = 0x%02x, want 0x%02x", elem.Tag, berTagSequence)
	}
	if len(elem.Children) != 2 {
		t.Fatalf("children = %d, want 2", len(elem.Children))
	}
	if elem.Children[0].Tag != berTagInteger {
		t.Errorf("child[0] tag = 0x%02x, want 0x%02x", elem.Children[0].Tag, berTagInteger)
	}
	if elem.Children[1].Tag != berTagOctetString {
		t.Errorf("child[1] tag = 0x%02x, want 0x%02x", elem.Children[1].Tag, berTagOctetString)
	}
}

func TestBERBooleanRoundTrip(t *testing.T) {
	for _, val := range []bool{true, false} {
		encoded := berBoolean(val)
		elem, _, err := parseBERElement(encoded, 0)
		if err != nil {
			t.Errorf("berBoolean(%v): parse error: %v", val, err)
			continue
		}
		if elem.Tag != berTagBoolean {
			t.Errorf("berBoolean(%v): tag 0x%02x, want 0x%02x", val, elem.Tag, berTagBoolean)
		}
	}
}

func TestBEREnumeratedRoundTrip(t *testing.T) {
	for _, val := range []int{0, 1, 127} {
		encoded := berEnumerated(val)
		elem, _, err := parseBERElement(encoded, 0)
		if err != nil {
			t.Errorf("berEnumerated(%d): parse error: %v", val, err)
			continue
		}
		if elem.Tag != berTagEnumerated {
			t.Errorf("berEnumerated(%d): tag 0x%02x, want 0x%02x", val, elem.Tag, berTagEnumerated)
		}
	}
}

func TestParseBERElementTruncated(t *testing.T) {
	// Empty data
	_, _, err := parseBERElement(nil, 0)
	if err == nil {
		t.Error("expected error on nil data")
	}

	// Tag only, no length
	_, _, err = parseBERElement([]byte{0x02}, 0)
	if err == nil {
		t.Error("expected error on tag-only data")
	}

	// Tag + length says 10, but only 2 bytes of value
	_, _, err = parseBERElement([]byte{0x02, 0x0a, 0x01, 0x02}, 0)
	if err == nil {
		t.Error("expected error on truncated value")
	}

	// Multi-byte length truncated
	_, _, err = parseBERElement([]byte{0x02, 0x82}, 0)
	if err == nil {
		t.Error("expected error on truncated multi-byte length")
	}
}

func TestParseBERLengthIndefinite(t *testing.T) {
	// Indefinite length (0x80) is not supported
	_, _, err := parseBERLength([]byte{0x80}, 0)
	if err == nil {
		t.Error("expected error on indefinite length")
	}
}

func TestBuildRootDSESearchParseable(t *testing.T) {
	msg := buildRootDSESearch(3)
	elem, consumed, err := parseBERElement(msg, 0)
	if err != nil {
		t.Fatalf("parse RootDSE search: %v", err)
	}
	if consumed != len(msg) {
		t.Errorf("consumed %d, want %d", consumed, len(msg))
	}
	if elem.Tag != berTagSequence {
		t.Errorf("tag = 0x%02x, want 0x%02x (SEQUENCE)", elem.Tag, berTagSequence)
	}
	// Should have 2 children: messageID + SearchRequest
	if len(elem.Children) != 2 {
		t.Fatalf("children = %d, want 2", len(elem.Children))
	}
	// First child: messageID (INTEGER)
	if elem.Children[0].Tag != berTagInteger {
		t.Errorf("messageID tag = 0x%02x, want 0x%02x", elem.Children[0].Tag, berTagInteger)
	}
	// Second child: SearchRequest (APPLICATION 3 = 0x63)
	if elem.Children[1].Tag != 0x63 {
		t.Errorf("SearchRequest tag = 0x%02x, want 0x63", elem.Children[1].Tag)
	}
}

func TestBuildSTARTTLSRequestParseable(t *testing.T) {
	msg := buildSTARTTLSRequest(2)
	elem, consumed, err := parseBERElement(msg, 0)
	if err != nil {
		t.Fatalf("parse STARTTLS request: %v", err)
	}
	if consumed != len(msg) {
		t.Errorf("consumed %d, want %d", consumed, len(msg))
	}
	if elem.Tag != berTagSequence {
		t.Errorf("tag = 0x%02x, want 0x%02x (SEQUENCE)", elem.Tag, berTagSequence)
	}
	if len(elem.Children) != 2 {
		t.Fatalf("children = %d, want 2", len(elem.Children))
	}
	// Second child: ExtendedRequest (APPLICATION 23 = 0x77)
	if elem.Children[1].Tag != 0x77 {
		t.Errorf("ExtendedRequest tag = 0x%02x, want 0x77", elem.Children[1].Tag)
	}
}

func TestParseSearchResultEntry(t *testing.T) {
	// Build a synthetic SearchResultEntry message:
	// SEQUENCE { messageID(3), [APPLICATION 4] { dn, SEQUENCE OF { SEQUENCE { type, SET { val } } } } }
	attrType := berOctetString([]byte("supportedLDAPVersion"))
	attrVal := berOctetString([]byte("3"))
	attrSet := append([]byte{berTagSet}, append(berEncodeLength(len(attrVal)), attrVal...)...)
	attrSeq := berSequence(attrType, attrSet)
	attrsList := berSequence(attrSeq)
	dn := berOctetString(nil) // empty DN for RootDSE
	searchEntry := berApplicationConstructed(4, dn, attrsList)
	msg := berSequence(berInteger(3), searchEntry)

	parsed, err := parseLDAPMessages(msg)
	if err != nil {
		t.Fatalf("parseLDAPMessages: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("messages = %d, want 1", len(parsed))
	}
	attrs := parseSearchResultEntry(parsed[0])
	versions, ok := attrs["supportedldapversion"]
	if !ok {
		t.Fatal("expected supportedldapversion attribute")
	}
	if len(versions) != 1 || versions[0] != "3" {
		t.Errorf("supportedldapversion = %v, want [3]", versions)
	}
}

func TestParseResultCode(t *testing.T) {
	// Build a synthetic BindResponse: SEQUENCE { messageID(1), [APPLICATION 1] { resultCode(0), matchedDN, diagnosticMessage } }
	bindResp := berApplicationConstructed(1,
		berEnumerated(0),
		berOctetString(nil),
		berOctetString(nil),
	)
	msg := berSequence(berInteger(1), bindResp)
	parsed, err := parseLDAPMessages(msg)
	if err != nil {
		t.Fatalf("parseLDAPMessages: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("messages = %d, want 1", len(parsed))
	}
	code := parseResultCode(parsed[0])
	if code != 0 {
		t.Errorf("resultCode = %d, want 0", code)
	}
}

func TestToLowerASCII(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"hello", "hello"},
		{"HELLO", "hello"},
		{"Hello", "hello"},
		{"supportedLDAPVersion", "supportedldapversion"},
		{"", ""},
	}
	for _, tt := range tests {
		got := toLowerASCII(tt.input)
		if got != tt.expected {
			t.Errorf("toLowerASCII(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
