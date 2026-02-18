package snmp

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
		got := parseBERInt(elem)
		if got != val {
			t.Errorf("berInteger(%d): round-trip got %d", val, got)
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

func TestDecodeOID(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "sysDescr.0",
			data:     []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00},
			expected: "1.3.6.1.2.1.1.1.0",
		},
		{
			name:     "sysObjectID.0",
			data:     []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00},
			expected: "1.3.6.1.2.1.1.2.0",
		},
		{
			name: "multi-byte component (8072)",
			// 1.3.6.1.4.1.8072 → 0x2b, 0x06, 0x01, 0x04, 0x01, 0xbf, 0x08
			data:     []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xbf, 0x08},
			expected: "1.3.6.1.4.1.8072",
		},
		{
			name:     "empty",
			data:     nil,
			expected: "",
		},
		{
			name:     "single byte",
			data:     []byte{0x2b},
			expected: "1.3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeOID(tt.data)
			if got != tt.expected {
				t.Errorf("decodeOID(%x) = %q, want %q", tt.data, got, tt.expected)
			}
		})
	}
}

func TestCreateMultiOIDRequest(t *testing.T) {
	req := createMultiOIDRequest(0x01, [][]byte{oidSysObjectID, oidSysName})

	// Should be parseable
	elem, consumed, err := parseBERElement(req, 0)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if consumed != len(req) {
		t.Errorf("consumed %d, want %d", consumed, len(req))
	}
	if elem.Tag != berTagSequence {
		t.Errorf("tag = 0x%02x, want 0x%02x", elem.Tag, berTagSequence)
	}
	// SEQUENCE { version, community, GetRequest }
	if len(elem.Children) != 3 {
		t.Fatalf("children = %d, want 3", len(elem.Children))
	}
	// Version should be integer 1 (v2c)
	if parseBERInt(elem.Children[0]) != 1 {
		t.Errorf("version = %d, want 1", parseBERInt(elem.Children[0]))
	}
	// Community should be "public"
	if string(elem.Children[1].Data) != "public" {
		t.Errorf("community = %q, want %q", string(elem.Children[1].Data), "public")
	}
	// Third child: GetRequest (0xa0)
	pdu := elem.Children[2]
	if pdu.Tag != 0xa0 {
		t.Errorf("PDU tag = 0x%02x, want 0xa0", pdu.Tag)
	}
	// PDU has 4 children: reqid, error-status, error-index, varbind-list
	if len(pdu.Children) != 4 {
		t.Fatalf("PDU children = %d, want 4", len(pdu.Children))
	}
	// Varbind-list should have 2 varbinds
	varbindList := pdu.Children[3]
	if len(varbindList.Children) != 2 {
		t.Errorf("varbinds = %d, want 2", len(varbindList.Children))
	}
}

func TestParseSNMPv1v2Response(t *testing.T) {
	// Build a synthetic GetResponse with a sysDescr varbind
	varbind := berSequence(
		berOID(oidSysDescr),
		berOctetString([]byte("Linux myhost 5.4.0")),
	)
	varbindList := berSequence(varbind)
	getResponse := berContextConstructed(2, // GetResponse = 0xa2
		berInteger(0x7fffffff), // request ID
		berInteger(0),          // error-status
		berInteger(0),          // error-index
		varbindList,
	)
	msg := berSequence(
		berInteger(1),                    // version v2c
		berOctetString([]byte("public")), // community
		getResponse,
	)

	result := parseSNMPv1v2Response(msg)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	val, ok := result["1.3.6.1.2.1.1.1.0"]
	if !ok {
		t.Fatal("expected sysDescr OID in result")
	}
	if val != "Linux myhost 5.4.0" {
		t.Errorf("sysDescr = %q, want %q", val, "Linux myhost 5.4.0")
	}
}

func TestParseSNMPv1v2ResponseErrorStatus(t *testing.T) {
	varbind := berSequence(
		berOID(oidSysDescr),
		berOctetString([]byte("test")),
	)
	varbindList := berSequence(varbind)
	getResponse := berContextConstructed(2,
		berInteger(1),
		berInteger(2), // error-status != 0
		berInteger(1),
		varbindList,
	)
	msg := berSequence(
		berInteger(1),
		berOctetString([]byte("public")),
		getResponse,
	)

	result := parseSNMPv1v2Response(msg)
	if result != nil {
		t.Errorf("expected nil result for error-status != 0, got %v", result)
	}
}

func TestParseSNMPv1v2ResponseInvalid(t *testing.T) {
	// Truncated data
	if parseSNMPv1v2Response([]byte{0x30, 0x01}) != nil {
		t.Error("expected nil for truncated data")
	}

	// Wrong PDU tag (GetRequest 0xa0 instead of GetResponse 0xa2)
	getReq := berContextConstructed(0,
		berInteger(1),
		berInteger(0),
		berInteger(0),
		berSequence(),
	)
	msg := berSequence(
		berInteger(1),
		berOctetString([]byte("public")),
		getReq,
	)
	if parseSNMPv1v2Response(msg) != nil {
		t.Error("expected nil for wrong PDU tag")
	}

	// nil data
	if parseSNMPv1v2Response(nil) != nil {
		t.Error("expected nil for nil data")
	}
}

func TestParseSNMPv3Response(t *testing.T) {
	// Build a synthetic v3 report with known engine values
	engineIDBytes := []byte{0x80, 0x00, 0x1f, 0x88, 0x80}
	secParams := berSequence(
		berOctetString(engineIDBytes), // engineID
		berInteger(42),                // boots
		berInteger(12345),             // time
		berOctetString(nil),           // user
		berOctetString(nil),           // auth
		berOctetString(nil),           // priv
	)
	msg := berSequence(
		berInteger(3),             // version
		berSequence(),             // globalData (placeholder)
		berOctetString(secParams), // securityParams (OCTET STRING wrapping SEQUENCE)
		berSequence(),             // scopedPDU (placeholder)
	)

	engineID, boots, engineTime, ok := parseSNMPv3Response(msg)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(engineID) != len(engineIDBytes) {
		t.Fatalf("engineID length = %d, want %d", len(engineID), len(engineIDBytes))
	}
	for i := range engineID {
		if engineID[i] != engineIDBytes[i] {
			t.Errorf("engineID[%d] = 0x%02x, want 0x%02x", i, engineID[i], engineIDBytes[i])
		}
	}
	if boots != 42 {
		t.Errorf("boots = %d, want 42", boots)
	}
	if engineTime != 12345 {
		t.Errorf("time = %d, want 12345", engineTime)
	}
}

func TestParseSNMPv3ResponseInvalid(t *testing.T) {
	// Truncated data
	_, _, _, ok := parseSNMPv3Response([]byte{0x30, 0x01})
	if ok {
		t.Error("expected ok=false for truncated data")
	}

	// Wrong version (v2c = 1)
	msg := berSequence(
		berInteger(1),       // version 1 (not 3)
		berSequence(),       // globalData
		berOctetString(nil), // securityParams
		berSequence(),       // scopedPDU
	)
	_, _, _, ok = parseSNMPv3Response(msg)
	if ok {
		t.Error("expected ok=false for wrong version")
	}

	// nil data
	_, _, _, ok = parseSNMPv3Response(nil)
	if ok {
		t.Error("expected ok=false for nil data")
	}
}
