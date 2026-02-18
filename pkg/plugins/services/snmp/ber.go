package snmp

import "fmt"

// BER tag constants
const (
	berTagInteger     = 0x02
	berTagOctetString = 0x04
	berTagNull        = 0x05
	berTagOID         = 0x06
	berTagSequence    = 0x30
)

// SNMP PDU tags (context-specific, constructed)
const (
	snmpGetResponse = 0xa2 // context 2, constructed
)

// berElement represents a parsed BER TLV element.
type berElement struct {
	Tag      byte
	Data     []byte // raw value bytes (without tag+length)
	Children []berElement
}

// --- Encoding ---

// berEncodeLength encodes a BER length field.
func berEncodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	buf := make([]byte, 0, 4)
	n := length
	for n > 0 {
		buf = append(buf, byte(n&0xff))
		n >>= 8
	}
	// Reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return append([]byte{byte(0x80 | len(buf))}, buf...)
}

// berInteger encodes an integer as BER.
func berInteger(value int) []byte {
	if value == 0 {
		return []byte{berTagInteger, 1, 0}
	}
	var buf []byte
	v := value
	if v > 0 {
		for v > 0 {
			buf = append([]byte{byte(v & 0xff)}, buf...)
			v >>= 8
		}
		if buf[0]&0x80 != 0 {
			buf = append([]byte{0}, buf...)
		}
	} else {
		for v < -1 {
			buf = append([]byte{byte(v & 0xff)}, buf...)
			v >>= 8
		}
		buf = append([]byte{byte(v & 0xff)}, buf...)
	}
	return append([]byte{berTagInteger}, append(berEncodeLength(len(buf)), buf...)...)
}

// berOctetString encodes a byte slice as a BER octet string.
func berOctetString(data []byte) []byte {
	return append([]byte{berTagOctetString}, append(berEncodeLength(len(data)), data...)...)
}

// berNull encodes a BER NULL.
func berNull() []byte {
	return []byte{berTagNull, 0x00}
}

// berSequence wraps children in a SEQUENCE.
func berSequence(children ...[]byte) []byte {
	var inner []byte
	for _, c := range children {
		inner = append(inner, c...)
	}
	return append([]byte{berTagSequence}, append(berEncodeLength(len(inner)), inner...)...)
}

// berOID wraps raw OID bytes with tag 0x06.
func berOID(oidBytes []byte) []byte {
	return append([]byte{berTagOID}, append(berEncodeLength(len(oidBytes)), oidBytes...)...)
}

// berContextConstructed wraps children in a context-specific constructed element.
func berContextConstructed(tag int, children ...[]byte) []byte {
	var inner []byte
	for _, c := range children {
		inner = append(inner, c...)
	}
	t := byte(0xa0 | (tag & 0x1f))
	return append([]byte{t}, append(berEncodeLength(len(inner)), inner...)...)
}

// --- Decoding ---

// parseBERLength parses a BER length at offset, returning (length, bytesConsumed, error).
func parseBERLength(data []byte, offset int) (int, int, error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("BER length: offset %d beyond data length %d", offset, len(data))
	}
	b := data[offset]
	if b < 0x80 {
		return int(b), 1, nil
	}
	numBytes := int(b & 0x7f)
	if numBytes == 0 {
		return 0, 0, fmt.Errorf("BER indefinite length not supported")
	}
	if offset+1+numBytes > len(data) {
		return 0, 0, fmt.Errorf("BER length: need %d bytes at offset %d, have %d", numBytes, offset+1, len(data)-offset-1)
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[offset+1+i])
	}
	return length, 1 + numBytes, nil
}

// parseBERElement parses a single BER element at offset.
func parseBERElement(data []byte, offset int) (berElement, int, error) {
	if offset >= len(data) {
		return berElement{}, 0, fmt.Errorf("BER element: offset %d beyond data length %d", offset, len(data))
	}
	tag := data[offset]
	length, lenBytes, err := parseBERLength(data, offset+1)
	if err != nil {
		return berElement{}, 0, fmt.Errorf("BER element tag 0x%02x: %w", tag, err)
	}
	headerLen := 1 + lenBytes
	valueStart := offset + headerLen
	valueEnd := valueStart + length
	if valueEnd > len(data) {
		return berElement{}, 0, fmt.Errorf("BER element tag 0x%02x: value extends beyond data (need %d, have %d)", tag, valueEnd, len(data))
	}
	elem := berElement{
		Tag:  tag,
		Data: data[valueStart:valueEnd],
	}
	if isConstructed(tag) {
		children, err := parseBERChildren(elem.Data)
		if err == nil {
			elem.Children = children
		}
	}
	return elem, headerLen + length, nil
}

// isConstructed returns true if the BER tag indicates a constructed type.
func isConstructed(tag byte) bool {
	return tag&0x20 != 0
}

// parseBERChildren parses all BER elements within a constructed element's value bytes.
func parseBERChildren(data []byte) ([]berElement, error) {
	var children []berElement
	offset := 0
	for offset < len(data) {
		child, consumed, err := parseBERElement(data, offset)
		if err != nil {
			return children, err
		}
		children = append(children, child)
		offset += consumed
	}
	return children, nil
}

// --- SNMP-specific ---

// decodeOID decodes BER OID value bytes into a dotted string (e.g. "1.3.6.1.2.1.1.1.0").
func decodeOID(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	// First byte encodes two components: first = b/40, second = b%40
	first := int(data[0]) / 40
	second := int(data[0]) % 40
	result := fmt.Sprintf("%d.%d", first, second)

	// Remaining bytes: base-128 variable-length encoding
	var val int
	for i := 1; i < len(data); i++ {
		val = (val << 7) | int(data[i]&0x7f)
		if data[i]&0x80 == 0 {
			result += fmt.Sprintf(".%d", val)
			val = 0
		}
	}
	return result
}

// parseBERInt extracts an integer from a BER element's data (big-endian, signed).
func parseBERInt(elem berElement) int {
	if len(elem.Data) == 0 {
		return 0
	}
	val := 0
	// Handle sign extension for negative numbers
	if elem.Data[0]&0x80 != 0 {
		val = -1
	}
	for _, b := range elem.Data {
		val = (val << 8) | int(b)
	}
	return val
}
