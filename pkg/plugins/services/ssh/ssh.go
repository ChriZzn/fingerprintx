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

package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"github.com/chrizzn/fingerprintx/third_party/cryptolib/ssh"
)

type Plugin struct{}

const SSH = "ssh"

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// https://www.rfc-editor.org/rfc/rfc4253.html#section-4
// from the RFC, two things:
// When the connection has been established, both sides MUST send an
// identification string.  This identification string MUST be
//
//	SSH-protoversion-softwareversion SP comments CR LF
//
// The server MAY send other lines of data before sending the version
//
//	string.  Each line SHOULD be terminated by a Carriage Return and Line
//	Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
//	in ISO-10646 UTF-8 [RFC3629] (language is not specified).
func checkSSH(data []byte) (string, error) {
	msgLength := len(data)
	if msgLength < 4 {
		return "", &shared.InvalidResponseErrorInfo{Service: SSH, Info: "response too short"}
	}
	sshID := []byte("SSH-")
	if bytes.Equal(data[:4], sshID) {
		return string(data), nil
	}

	for _, line := range strings.Split(string(data), "\r\n") {
		if len(line) >= 4 && line[:4] == "SSH-" {
			return line, nil
		}
	}

	return "", &shared.InvalidResponseErrorInfo{Service: SSH, Info: "invalid banner prefix"}
}

func checkAlgo(data []byte) (map[string]string, error) {
	length := len(data)
	if length < 26 {
		return nil, fmt.Errorf("invalid response length")
	}
	cookie := hex.EncodeToString(data[6:22])

	kexAlgorithmsLength := int(big.NewInt(0).SetBytes(data[22:26]).Uint64())
	if length < 26+kexAlgorithmsLength {
		return nil, fmt.Errorf("invalid response length")
	}
	kexAlgos := string(data[26 : 26+kexAlgorithmsLength])

	sHKAlgoBegin := 26 + kexAlgorithmsLength
	if length < 4+sHKAlgoBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	sHKAlgoLength := int(big.NewInt(0).SetBytes(data[sHKAlgoBegin : 4+sHKAlgoBegin]).Uint64())
	if length < 4+sHKAlgoBegin+sHKAlgoLength {
		return nil, fmt.Errorf("invalid response length")
	}
	serverHostKeyAlgos := string(data[4+sHKAlgoBegin : 4+sHKAlgoBegin+sHKAlgoLength])

	encryptAlgoCToSBegin := 4 + sHKAlgoBegin + sHKAlgoLength
	if length < 4+encryptAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	encryptAlgoCToSLength := int(big.NewInt(0).SetBytes(data[encryptAlgoCToSBegin : 4+encryptAlgoCToSBegin]).Uint64())
	if length < 4+encryptAlgoCToSBegin+encryptAlgoCToSLength {
		return nil, fmt.Errorf("invalid response length")
	}
	ciphersClientServer := string(data[4+encryptAlgoCToSBegin : 4+encryptAlgoCToSBegin+encryptAlgoCToSLength])

	encryptAlgoSToCBegin := 4 + encryptAlgoCToSBegin + encryptAlgoCToSLength
	if length < 4+encryptAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	encryptAlgoSToCLength := int(big.NewInt(0).SetBytes(data[encryptAlgoSToCBegin : 4+encryptAlgoSToCBegin]).Uint64())
	if length < 4+encryptAlgoCToSBegin+encryptAlgoSToCLength {
		return nil, fmt.Errorf("invalid response length")
	}
	ciphersServerClient := string(data[4+encryptAlgoSToCBegin : 4+encryptAlgoSToCBegin+encryptAlgoSToCLength])

	macAlgoCToSBegin := 4 + encryptAlgoSToCBegin + encryptAlgoSToCLength
	if length < 4+macAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	macAlgoCToSLength := int(big.NewInt(0).SetBytes(data[macAlgoCToSBegin : 4+macAlgoCToSBegin]).Uint64())
	if length < 4+macAlgoCToSBegin+macAlgoCToSLength {
		return nil, fmt.Errorf("invalid response length")
	}
	macClientServer := string(data[4+macAlgoCToSBegin : 4+macAlgoCToSBegin+macAlgoCToSLength])

	macAlgoSToCBegin := 4 + macAlgoCToSBegin + macAlgoCToSLength
	if length < 4+macAlgoSToCBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	macAlgoSToCLength := int(big.NewInt(0).SetBytes(data[macAlgoSToCBegin : 4+macAlgoSToCBegin]).Uint64())
	if length < 4+macAlgoSToCBegin+macAlgoCToSLength {
		return nil, fmt.Errorf("invalid response length")
	}
	macServerClient := string(data[4+macAlgoSToCBegin : 4+macAlgoSToCBegin+macAlgoSToCLength])

	compAlgoCToSBegin := 4 + macAlgoSToCBegin + macAlgoSToCLength
	if length < 4+compAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	compAlgoCToSLength := int(big.NewInt(0).SetBytes(data[compAlgoCToSBegin : 4+compAlgoCToSBegin]).Uint64())
	if length < 4+compAlgoCToSBegin+compAlgoCToSLength {
		return nil, fmt.Errorf("invalid response length")
	}
	compressionClientServer := string(data[4+compAlgoCToSBegin : 4+compAlgoCToSBegin+compAlgoCToSLength])

	compAlgoSToCBegin := 4 + compAlgoCToSBegin + compAlgoCToSLength
	if length < 4+compAlgoSToCBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	compAlgoSToCLength := int(big.NewInt(0).SetBytes(data[compAlgoSToCBegin : 4+compAlgoSToCBegin]).Uint64())
	if length < 4+compAlgoSToCBegin+compAlgoSToCLength {
		return nil, fmt.Errorf("invalid response length")
	}
	compressionServerClient := string(data[4+compAlgoSToCBegin : 4+compAlgoSToCBegin+compAlgoSToCLength])

	langAlgoCToSBegin := 4 + compAlgoSToCBegin + compAlgoSToCLength
	if length < 4+langAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	langAlgoCToSLength := int(big.NewInt(0).SetBytes(data[langAlgoCToSBegin : 4+langAlgoCToSBegin]).Uint64())
	if length < 4+langAlgoCToSBegin+langAlgoCToSLength {
		return nil, fmt.Errorf("invalid response length")
	}
	languagesClientServer := string(data[4+langAlgoCToSBegin : 4+langAlgoCToSBegin+langAlgoCToSLength])

	langAlgoSToCBegin := 4 + langAlgoCToSBegin + langAlgoCToSLength
	if length < 4+langAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	langAlgoSToCLength := int(big.NewInt(0).SetBytes(data[langAlgoSToCBegin : 4+langAlgoSToCBegin]).Uint64())
	if length < 4+langAlgoCToSBegin+langAlgoSToCLength {
		return nil, fmt.Errorf("invalid response length")
	}
	languagesServerClient := string(data[4+langAlgoSToCBegin : 4+langAlgoSToCBegin+langAlgoSToCLength])

	info := map[string]string{
		"Cookie":                  cookie,
		"KexAlgos":                kexAlgos,
		"ServerHostKeyAlgos":      serverHostKeyAlgos,
		"CiphersClientServer":     ciphersClientServer,
		"CiphersServerClient":     ciphersServerClient,
		"MACsClientServer":        macClientServer,
		"MACsServerClient":        macServerClient,
		"CompressionClientServer": compressionClientServer,
		"CompressionServerClient": compressionServerClient,
		"LanguagesClientServer":   languagesClientServer,
		"LanguagesServerClient":   languagesServerClient,
	}

	return info, nil
}

// parseBanner parses an SSH identification string per RFC 4253 §4.2.
// Format: SSH-protoversion-softwareversion SP comments CR LF
// Returns empty strings on malformed input.
func parseBanner(banner string) (proto, software, comments string) {
	banner = strings.TrimRight(banner, "\r\n")
	if !strings.HasPrefix(banner, "SSH-") {
		return "", "", ""
	}
	rest := banner[4:] // strip "SSH-"

	dashIdx := strings.Index(rest, "-")
	if dashIdx < 0 {
		return "", "", ""
	}
	proto = rest[:dashIdx]
	rest = rest[dashIdx+1:]

	spaceIdx := strings.Index(rest, " ")
	if spaceIdx < 0 {
		software = rest
		return proto, software, ""
	}
	software = rest[:spaceIdx]
	comments = rest[spaceIdx+1:]
	return proto, software, comments
}

// algoMapToStruct converts the checkAlgo() map output to a structured SSHAlgorithms.
func algoMapToStruct(algo map[string]string) *SSHAlgorithms {
	if algo == nil {
		return nil
	}
	splitNonEmpty := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, ",")
	}
	return &SSHAlgorithms{
		KexAlgorithms:             splitNonEmpty(algo["KexAlgos"]),
		ServerHostKeyAlgorithms:   splitNonEmpty(algo["ServerHostKeyAlgos"]),
		CiphersClientToServer:     splitNonEmpty(algo["CiphersClientServer"]),
		CiphersServerToClient:     splitNonEmpty(algo["CiphersServerClient"]),
		MACsClientToServer:        splitNonEmpty(algo["MACsClientServer"]),
		MACsServerToClient:        splitNonEmpty(algo["MACsServerClient"]),
		CompressionClientToServer: splitNonEmpty(algo["CompressionClientServer"]),
		CompressionServerToClient: splitNonEmpty(algo["CompressionServerClient"]),
	}
}

// probeAuthMethods probes an SSH server for supported authentication methods.
// It generates a throwaway ed25519 key and attempts publickey + password +
// keyboard-interactive auth, then parses the attempted methods from the error.
// Returns nil on any failure (best-effort).
func probeAuthMethods(address string, timeout time.Duration) ([]string, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, err
	}

	conf := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
			ssh.Password("admin"),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = "password"
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	conf.KeyExchanges = append(conf.KeyExchanges,
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group14-sha256",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"curve25519-sha256@libssh.org",
		"curve25519-sha256",
	)
	conf.Ciphers = append(conf.Ciphers,
		"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"arcfour256", "arcfour128", "arcfour",
		"aes128-cbc",
		"3des-cbc",
	)

	client, err := ssh.Dial("tcp", address, conf)
	if err != nil {
		methods := parseAttemptedMethods(err.Error())
		return methods, nil
	}
	client.Close()
	return nil, nil
}

// parseAttemptedMethods extracts auth method names from an SSH error message.
// Example: "ssh: handshake failed: ssh: unable to authenticate, attempted methods [publickey password keyboard-interactive], no supported methods remain"
func parseAttemptedMethods(errMsg string) []string {
	const marker = "attempted methods ["
	idx := strings.Index(errMsg, marker)
	if idx < 0 {
		return nil
	}
	rest := errMsg[idx+len(marker):]
	endIdx := strings.Index(rest, "]")
	if endIdx < 0 {
		return nil
	}
	methods := rest[:endIdx]
	if methods == "" {
		return nil
	}
	return strings.Fields(methods)
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	var (
		banner             string
		algo               map[string]string
		algorithms         *SSHAlgorithms
		authMethods        []string
		base64HostKey      string
		hostKeyType        string
		hostKeyFingerprint string
	)

	response, err := shared.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	banner, err = checkSSH(response)
	if err != nil {
		return nil, err
	}

	protoVersion, softwareVersion, comments := parseBanner(banner)

	msg := []byte("SSH-2.0-Fingerprintx-SSH2\r\n")
	response, err = shared.SendRecv(conn, msg, timeout)
	if err != nil {
		return nil, err
	}

	algo, err = checkAlgo(response)
	if err == nil {
		algorithms = algoMapToStruct(algo)

		// probe auth methods (best-effort)
		if methods, probeErr := probeAuthMethods(target.Address.String(), timeout); probeErr == nil {
			authMethods = methods
		}

		sshConfig := &ssh.ClientConfig{}
		fullConf := *sshConfig
		fullConf.SetDefaults()

		c := ssh.NewTransport(conn, fullConf.Rand, true)
		t := ssh.NewHandshakeTransport(c, &fullConf.Config, msg, []byte(banner))
		sendMsg := ssh.KexInitMsg{
			KexAlgos:                t.Config.KeyExchanges,
			CiphersClientServer:     t.Config.Ciphers,
			CiphersServerClient:     t.Config.Ciphers,
			MACsClientServer:        t.Config.MACs,
			MACsServerClient:        t.Config.MACs,
			ServerHostKeyAlgos:      ssh.SupportedHostKeyAlgos,
			CompressionClientServer: []string{"none"},
			CompressionServerClient: []string{"none"},
		}

		if err = func() error {
			if _, err := io.ReadFull(rand.Reader, sendMsg.Cookie[:]); err != nil {
				return err
			}

			if firstKeyExchange := t.SessionID == nil; firstKeyExchange {
				sendMsg.KexAlgos = make([]string, 0, len(t.Config.KeyExchanges)+1)
				sendMsg.KexAlgos = append(sendMsg.KexAlgos, t.Config.KeyExchanges...)
				sendMsg.KexAlgos = append(sendMsg.KexAlgos, "ext-info-c")
			}

			packet := ssh.Marshal(sendMsg)
			packetCopy := make([]byte, len(packet))
			copy(packetCopy, packet)

			if err := ssh.PushPacket(t.HandshakeTransport, packetCopy); err != nil {
				return err
			}

			cookie, err := hex.DecodeString(algo["cookie"])
			if err != nil {
				return err
			}

			var ret [16]byte
			copy(ret[:], cookie)

			otherInit := &ssh.KexInitMsg{
				KexAlgos:                strings.Split(algo["KexAlgos"], ","),
				Cookie:                  ret,
				ServerHostKeyAlgos:      strings.Split(algo["ServerHostKeyAlgos"], ","),
				CiphersClientServer:     strings.Split(algo["CiphersClientServer"], ","),
				CiphersServerClient:     strings.Split(algo["CiphersServerClient"], ","),
				MACsClientServer:        strings.Split(algo["MACsClientServer"], ","),
				MACsServerClient:        strings.Split(algo["MACsServerClient"], ","),
				CompressionClientServer: strings.Split(algo["CompressionClientServer"], ","),
				CompressionServerClient: strings.Split(algo["CompressionServerClient"], ","),
				FirstKexFollows:         false,
				Reserved:                0,
			}

			t.Algorithms, err = ssh.FindAgreedAlgorithms(false, &sendMsg, otherInit)
			if err != nil {
				return err
			}

			magics := ssh.HandshakeMagics{
				ClientVersion: t.ClientVersion,
				ServerVersion: t.ServerVersion,
				ClientKexInit: packet,
				ServerKexInit: response[5 : len(response)-10],
			}

			kex := ssh.GetKex(t.Algorithms.Kex)
			result, err := ssh.Clients(t, kex, &magics)
			if err != nil {
				return err
			}

			hostKey, err := ssh.ParsePublicKey(result.HostKey)
			if err != nil {
				return err
			}

			hostKeyFingerprint = ssh.FingerprintSHA256(hostKey)
			base64HostKey = base64.StdEncoding.EncodeToString(result.HostKey)
			hostKeyType = hostKey.Type()
			return nil
		}(); err != nil {
			// Error occurred during the handshake process - continue with basic info
		}
	}

	passwordAuth := false
	for _, m := range authMethods {
		if m == "password" || m == "keyboard-interactive" {
			passwordAuth = true
			break
		}
	}

	payload := ServiceSSH{
		Banner:              banner,
		ProtocolVersion:     protoVersion,
		SoftwareVersion:     softwareVersion,
		Comments:            comments,
		Algorithms:          algorithms,
		AuthMethods:         authMethods,
		PasswordAuthEnabled: passwordAuth,
	}

	if base64HostKey != "" {
		payload.HostKey = base64HostKey
		payload.HostKeyType = hostKeyType
		payload.HostKeyFingerprint = hostKeyFingerprint
	}

	return plugins.CreateServiceFrom(target, p.Name(), payload, conn.TLS()), nil
}

func (p *Plugin) Name() string {
	return SSH
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 2
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{22, 2222, 22222, 2244, 24442}
}
