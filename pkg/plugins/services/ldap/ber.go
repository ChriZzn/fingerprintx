package ldap

import "fmt"

// BER tag constants
const (
	berTagBoolean     = 0x01
	berTagInteger     = 0x02
	berTagOctetString = 0x04
	berTagEnumerated  = 0x0a
	berTagSequence    = 0x30
	berTagSet         = 0x31
)

// LDAP application tags (constructed)
const (
	ldapBindResponse      = 0x61 // application 1, constructed
	ldapSearchResultEntry = 0x64 // application 4, constructed
	ldapSearchResultDone  = 0x65 // application 5, constructed
	ldapExtendedResponse  = 0x78 // application 24, constructed
)

// LDAP OIDs
const (
	oidSTARTTLS = "1.3.6.1.4.1.1466.20037"
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
	// Determine how many bytes needed
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
	// Encode value as big-endian bytes with sign
	var buf []byte
	v := value
	if v > 0 {
		for v > 0 {
			buf = append([]byte{byte(v & 0xff)}, buf...)
			v >>= 8
		}
		// Add leading zero if high bit set (positive number)
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

// berEnumerated encodes an enumerated value.
func berEnumerated(value int) []byte {
	if value >= 0 && value < 128 {
		return []byte{berTagEnumerated, 1, byte(value)}
	}
	// Reuse integer encoding logic but swap tag
	encoded := berInteger(value)
	encoded[0] = berTagEnumerated
	return encoded
}

// berBoolean encodes a boolean.
func berBoolean(value bool) []byte {
	if value {
		return []byte{berTagBoolean, 1, 0xff}
	}
	return []byte{berTagBoolean, 1, 0x00}
}

// berSequence wraps children in a SEQUENCE.
func berSequence(children ...[]byte) []byte {
	var inner []byte
	for _, c := range children {
		inner = append(inner, c...)
	}
	return append([]byte{berTagSequence}, append(berEncodeLength(len(inner)), inner...)...)
}

// berApplicationConstructed wraps children in an application-tagged constructed element.
func berApplicationConstructed(tag int, children ...[]byte) []byte {
	var inner []byte
	for _, c := range children {
		inner = append(inner, c...)
	}
	t := byte(0x60 | (tag & 0x1f)) // class=application, constructed
	return append([]byte{t}, append(berEncodeLength(len(inner)), inner...)...)
}

// berContextPrimitive encodes a context-specific primitive value.
func berContextPrimitive(tag int, data []byte) []byte {
	t := byte(0x80 | (tag & 0x1f)) // class=context, primitive
	return append([]byte{t}, append(berEncodeLength(len(data)), data...)...)
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
// Returns the element and the total bytes consumed (tag + length + value).
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
	// Auto-parse children for constructed types
	if isConstructed(tag) {
		children, err := parseBERChildren(elem.Data)
		if err == nil {
			elem.Children = children
		}
		// If parsing children fails, we still have the raw Data
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

// --- LDAP Message Builders ---

// buildRootDSESearch builds an LDAP SearchRequest for the RootDSE (base "", scope=base, attrs=*,+).
func buildRootDSESearch(messageID int) []byte {
	// SearchRequest ::= [APPLICATION 3] SEQUENCE {
	//   baseObject    LDAPDN (empty string),
	//   scope         ENUMERATED { baseObject(0) },
	//   derefAliases  ENUMERATED { neverDerefAliases(0) },
	//   sizeLimit     INTEGER (0 = no limit),
	//   timeLimit     INTEGER (0 = no limit),
	//   typesOnly     BOOLEAN (FALSE),
	//   filter        [context 7] present "objectClass",
	//   attributes    SEQUENCE OF { "*", "+" }
	// }
	searchRequest := berApplicationConstructed(3,
		berOctetString(nil), // baseObject: ""
		berEnumerated(0),    // scope: baseObject
		berEnumerated(0),    // derefAliases: neverDerefAliases
		berInteger(0),       // sizeLimit: 0
		berInteger(0),       // timeLimit: 0
		berBoolean(false),   // typesOnly: false
		berContextPrimitive(7, []byte("objectClass")), // filter: (objectClass=*)
		berSequence( // attributes
			berOctetString([]byte("*")),
			berOctetString([]byte("+")),
		),
	)
	return berSequence(berInteger(messageID), searchRequest)
}

// buildSTARTTLSRequest builds an LDAP ExtendedRequest for STARTTLS (OID 1.3.6.1.4.1.1466.20037).
func buildSTARTTLSRequest(messageID int) []byte {
	// ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
	//   requestName  [0] LDAPOID
	// }
	extReq := berApplicationConstructed(23,
		berContextPrimitive(0, []byte(oidSTARTTLS)),
	)
	return berSequence(berInteger(messageID), extReq)
}

// --- LDAP Response Parsers ---

// parseLDAPMessages parses one or more LDAP message envelopes from raw bytes.
// Each message is: SEQUENCE { messageID INTEGER, protocolOp, ... }
func parseLDAPMessages(data []byte) ([]berElement, error) {
	var messages []berElement
	offset := 0
	for offset < len(data) {
		elem, consumed, err := parseBERElement(data, offset)
		if err != nil {
			return messages, err
		}
		messages = append(messages, elem)
		offset += consumed
	}
	return messages, nil
}

// parseSearchResultEntry extracts attributes from a SearchResultEntry.
// SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
//
//	objectName  LDAPDN,
//	attributes  SEQUENCE OF { SEQUENCE { type, SET OF value } }
//
// }
// Returns a map of attribute name (lowercased) to list of string values.
func parseSearchResultEntry(elem berElement) map[string][]string {
	attrs := make(map[string][]string)
	if len(elem.Children) < 2 {
		return attrs
	}

	// Find the protocolOp (second child of the message envelope)
	protocolOp := elem.Children[1]
	if protocolOp.Tag != ldapSearchResultEntry {
		return attrs
	}
	if len(protocolOp.Children) < 2 {
		return attrs
	}

	// Second child of the SearchResultEntry is the attributes sequence
	attrList := protocolOp.Children[1]
	for _, attrSeq := range attrList.Children {
		if len(attrSeq.Children) < 2 {
			continue
		}
		attrName := string(attrSeq.Children[0].Data)
		valuesSet := attrSeq.Children[1] // SET OF values
		var values []string
		for _, v := range valuesSet.Children {
			values = append(values, string(v.Data))
		}
		attrs[toLowerASCII(attrName)] = values
	}
	return attrs
}

// parseResultCode extracts the result code from a BindResponse, SearchResultDone, or ExtendedResponse.
// These all have: [APPLICATION N] SEQUENCE { resultCode ENUMERATED, ... }
// Returns the result code or -1 on parse failure.
func parseResultCode(elem berElement) int {
	if len(elem.Children) < 2 {
		return -1
	}
	protocolOp := elem.Children[1]
	if len(protocolOp.Children) < 1 {
		return -1
	}
	resultElem := protocolOp.Children[0]
	if resultElem.Tag != berTagEnumerated {
		return -1
	}
	if len(resultElem.Data) == 0 {
		return -1
	}
	// Parse as unsigned int
	val := 0
	for _, b := range resultElem.Data {
		val = (val << 8) | int(b)
	}
	return val
}

// toLowerASCII lowercases ASCII letters without allocating for already-lowercase strings.
func toLowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			buf := []byte(s)
			for j := i; j < len(buf); j++ {
				if buf[j] >= 'A' && buf[j] <= 'Z' {
					buf[j] += 'a' - 'A'
				}
			}
			return string(buf)
		}
	}
	return s
}
