// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldap

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
)

type Plugin struct{}

const LDAP = "ldap"

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func generateRandomString(length int) []byte {
	charset := "abcdefghijklmnopqrstuvwxyz"
	result := make([]byte, length)

	for i := range result {
		result[i] = charset[rand.Intn(len(charset))] //nolint:gosec
	}
	return result
}

func generateBindRequestAndID() [2][]byte {
	sequenceBERHeader := [2]byte{0x30, 0x3a}
	messageID := uint32(rand.Int31()) //nolint:gosec
	messageIDBytes := [4]byte{}
	binary.BigEndian.PutUint32(messageIDBytes[:], messageID)
	messageIDBERHeader := [2]byte{0x02, 0x04}
	finalMessageIDBER := make([]byte, 6)
	copy(finalMessageIDBER[:2], messageIDBERHeader[:])
	copy(finalMessageIDBER[2:], messageIDBytes[:])
	bindRequestHeader := [2]byte{0x60, 0x32}
	versionBER := [3]byte{0x02, 0x01, 0x03}
	stringBERHeader := [2]byte{0x04, 0x17}
	stringContextBERHeader := [2]byte{0x80, 0x14}
	randomAlphaString := generateRandomString(20)
	dePrefix := []byte("cn=")
	distinguishedName := append(dePrefix, randomAlphaString...) //nolint:gocritic
	passwordBER := randomAlphaString
	combine := [][]byte{
		sequenceBERHeader[:],
		finalMessageIDBER,
		bindRequestHeader[:],
		versionBER[:],
		stringBERHeader[:],
		distinguishedName,
		stringContextBERHeader[:],
		passwordBER,
	}
	fullBindRequest := make([]byte, 60)
	index := 0
	for _, s := range combine {
		index += copy(fullBindRequest[index:], s)
	}

	return [2][]byte{fullBindRequest, finalMessageIDBER}
}

// DetectLDAP sends a bind request and validates the response format.
// Returns (detected, response bytes, error).
func DetectLDAP(conn net.Conn, timeout time.Duration) (bool, []byte, error) {
	requestAndID := generateBindRequestAndID()

	response, err := shared.SendRecv(conn, requestAndID[0], timeout)
	if err != nil {
		return false, nil, err
	}
	if len(response) == 0 {
		return false, nil, nil
	}

	expectedSequenceByte := byte(0x30)
	expectedMessageLengthByte := byte(len(response) - 2)
	expectedLDAPHeader := append(
		[]byte{expectedSequenceByte, expectedMessageLengthByte},
		requestAndID[1]...)

	if len(response) < 7 {
		return false, nil, nil
	}
	otherVersionResponse := append([]byte{response[0]}, response[5]+4)
	otherVersionResponse = append(otherVersionResponse, response[6:]...)

	if bytes.HasPrefix(response, expectedLDAPHeader) || bytes.HasPrefix(otherVersionResponse, expectedLDAPHeader) {
		return true, response, nil
	}
	return false, nil, nil
}

// trySTARTTLS attempts an LDAP STARTTLS extended operation on the connection.
// Returns true if the server accepted STARTTLS and the TLS upgrade succeeded.
// On any failure, returns false without affecting the connection's usability for
// further LDAP operations (unless the connection is broken).
func trySTARTTLS(conn *plugins.FingerprintConn, timeout time.Duration) bool {
	// Only attempt on non-TLS connections
	if conn.TLS() != nil {
		return false
	}

	req := buildSTARTTLSRequest(2)
	response, err := shared.SendRecv(conn, req, timeout)
	if err != nil || len(response) == 0 {
		return false
	}

	// Parse ExtendedResponse — check resultCode == 0 (success)
	messages, err := parseLDAPMessages(response)
	if err != nil || len(messages) == 0 {
		return false
	}
	if parseResultCode(messages[0]) != 0 {
		return false
	}

	// Upgrade to TLS
	conn.Upgrade()
	return conn.TLS() != nil
}

// queryRootDSE sends a SearchRequest for the RootDSE and returns parsed attributes.
// Returns nil on any error (graceful degradation).
func queryRootDSE(conn net.Conn, timeout time.Duration) map[string][]string {
	req := buildRootDSESearch(3)
	err := shared.Send(conn, req, timeout)
	if err != nil {
		return nil
	}

	// Read response — may arrive in multiple TCP segments.
	// We need SearchResultEntry + SearchResultDone.
	var buf []byte
	for i := 0; i < 3; i++ {
		chunk, err := shared.Recv(conn, timeout)
		if err != nil || len(chunk) == 0 {
			break
		}
		buf = append(buf, chunk...)

		// Check if we have a SearchResultDone (tag 0x65) — that terminates the search.
		if containsSearchResultDone(buf) {
			break
		}
	}
	if len(buf) == 0 {
		return nil
	}

	messages, err := parseLDAPMessages(buf)
	if err != nil && len(messages) == 0 {
		return nil
	}

	// Find the SearchResultEntry among the messages
	for _, msg := range messages {
		if len(msg.Children) >= 2 && msg.Children[1].Tag == ldapSearchResultEntry {
			return parseSearchResultEntry(msg)
		}
	}
	return nil
}

// containsSearchResultDone scans for the SearchResultDone tag (0x65) at a valid
// LDAP message boundary (inside a SEQUENCE 0x30).
func containsSearchResultDone(data []byte) bool {
	msgs, _ := parseLDAPMessages(data)
	for _, msg := range msgs {
		if len(msg.Children) >= 2 && msg.Children[1].Tag == ldapSearchResultDone {
			return true
		}
	}
	return false
}

// populateMetadata fills the ServiceLDAP struct from RootDSE attributes.
func populateMetadata(attrs map[string][]string) ServiceLDAP {
	svc := ServiceLDAP{}
	if attrs == nil {
		return svc
	}

	// Helper to get first value
	first := func(key string) string {
		if v, ok := attrs[key]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}

	// Standard RootDSE (RFC 4512)
	svc.NamingContexts = attrs["namingcontexts"]
	svc.SubschemaSubentry = first("subschemasubentry")
	svc.SupportedLDAPVersions = attrs["supportedldapversion"]
	svc.SupportedSASLMechs = attrs["supportedsaslmechanisms"]
	svc.SupportedExtensions = attrs["supportedextension"]
	svc.SupportedControls = attrs["supportedcontrol"]
	svc.VendorName = first("vendorname")
	svc.VendorVersion = first("vendorversion")

	// Active Directory
	svc.DNSHostName = first("dnshostname")
	svc.DefaultNamingContext = first("defaultnamingcontext")
	svc.DomainFunctionality = first("domainfunctionality")
	svc.ForestFunctionality = first("forestfunctionality")
	svc.DomainControllerFunctionality = first("domaincontrollerfunctionality")
	svc.ServerName = first("servername")
	svc.IsGlobalCatalogReady = first("isglobalcatalogready")

	return svc
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isLDAP, _, err := DetectLDAP(conn, timeout)
	if err != nil {
		return nil, err
	}
	if !isLDAP {
		return nil, nil
	}

	// LDAP detected — now gather metadata (all best-effort)

	// Try STARTTLS on non-TLS connections
	startTLS := trySTARTTLS(conn, timeout)

	// Query RootDSE for server info
	attrs := queryRootDSE(conn, timeout)

	// Build metadata
	svc := populateMetadata(attrs)
	svc.StartTLSSupported = startTLS

	return plugins.CreateServiceFrom(target, p.Name(), svc, conn.TLS()), nil
}

func (p *Plugin) Name() string {
	return LDAP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 175
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{389, 636}
}
