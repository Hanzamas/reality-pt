// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// The handshake below follows the REALITY client in Xray-core,
// transport/internet/reality/reality.go (MPL-2.0).

package reality

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/hanzamas/reality-pt/transport"
)

// The ClientHello session ID carries the authentication token. In the
// handshake message it starts 39 bytes in: 4 (handshake header) + 2 (version)
// + 32 (random) + 1 (session ID length).
const (
	sessionIDOffset = 39
	sessionIDLen    = 32
	randomLen       = 32

	// The first saltLen bytes of the ClientHello random salt the key
	// derivation, the rest is the AES-GCM nonce.
	saltLen = 20

	authKeyLen = 32
	tokenLen   = 16
	hkdfInfo   = "REALITY"
)

// clientVersion goes into the token. The server checks it only when it is
// configured with a minimum or maximum client version.
var clientVersion = [3]byte{0, 1, 0}

// ErrNotBridge means the peer did not prove to be the configured bridge. The
// public key or short ID is wrong, or the connection reached a cover site.
var ErrNotBridge = errors.New("reality: peer is not the configured bridge: wrong key or short ID, or a cover site answered")

var errHelloLayout = errors.New("reality: unexpected ClientHello layout")

// Client runs the client side of the handshake.
type Client struct {
	params ClientParams
	hello  utls.ClientHelloID
}

var _ transport.ClientStage = (*Client)(nil)

// NewClient checks the parameters and returns a Client.
func NewClient(p ClientParams) (*Client, error) {
	if p.Fingerprint == "" {
		p.Fingerprint = DefaultFingerprint
	}
	hello, err := lookupFingerprint(p.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("reality: %w", err)
	}
	return &Client{params: p, hello: hello}, nil
}

// NewClientStage is the transport.ClientFactory for REALITY.
func NewClientStage(args transport.Args) (transport.ClientStage, error) {
	p, err := ParseClientParams(args)
	if err != nil {
		return nil, err
	}
	c, err := NewClient(p)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Handshake implements transport.ClientStage. It sends a browser-shaped
// ClientHello that carries the authentication token and accepts the server
// only if its certificate proves knowledge of the shared key.
func (c *Client) Handshake(ctx context.Context, raw net.Conn) (net.Conn, error) {
	var authKey []byte
	uc := utls.UClient(raw, &utls.Config{
		ServerName: c.params.ServerName,
		// The bridge's certificate is checked by verifyBridgeCert, not
		// against a trust store.
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyBridgeCert(rawCerts, authKey)
		},
	}, c.hello)

	key, err := c.sealHello(uc)
	if err != nil {
		return nil, err
	}
	authKey = key

	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uc, nil
}

// sealHello writes the authentication token into the session ID of the
// ClientHello and returns the key the server will use to prove itself.
func (c *Client) sealHello(uc *utls.UConn) ([]byte, error) {
	if err := uc.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("reality: build ClientHello: %w", err)
	}
	hello := uc.HandshakeState.Hello
	if len(hello.Raw) < sessionIDOffset+sessionIDLen ||
		hello.Raw[sessionIDOffset-1] != sessionIDLen ||
		len(hello.Random) != randomLen {
		return nil, errHelloLayout
	}

	keys := uc.HandshakeState.State13.KeyShareKeys
	if keys == nil {
		return nil, errors.New("reality: ClientHello profile has no TLS 1.3 key share")
	}
	ephemeral := keys.Ecdhe
	if ephemeral == nil {
		ephemeral = keys.MlkemEcdhe
	}
	if ephemeral == nil {
		return nil, errors.New("reality: ClientHello profile has no X25519 key share")
	}

	serverKey, err := ecdh.X25519().NewPublicKey(c.params.PublicKey[:])
	if err != nil {
		return nil, fmt.Errorf("reality: bridge public key: %w", err)
	}
	shared, err := ephemeral.ECDH(serverKey)
	if err != nil {
		return nil, fmt.Errorf("reality: key agreement: %w", err)
	}
	authKey, err := hkdf.Key(sha256.New, shared, hello.Random[:saltLen], hkdfInfo, authKeyLen)
	if err != nil {
		return nil, fmt.Errorf("reality: derive key: %w", err)
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, fmt.Errorf("reality: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("reality: cipher: %w", err)
	}

	// The server authenticates the ClientHello with the session ID zeroed.
	sessionID := make([]byte, sessionIDLen)
	copy(hello.Raw[sessionIDOffset:], sessionID)

	copy(sessionID[0:3], clientVersion[:])
	binary.BigEndian.PutUint32(sessionID[4:8], uint32(time.Now().Unix()))
	copy(sessionID[8:tokenLen], c.params.ShortID[:])

	// Seal the 16-byte token in place: token plus 16-byte tag fill the
	// 32-byte session ID.
	aead.Seal(sessionID[:0], hello.Random[saltLen:], sessionID[:tokenLen], hello.Raw)
	hello.SessionId = sessionID
	copy(hello.Raw[sessionIDOffset:], sessionID)
	return authKey, nil
}

// verifyBridgeCert accepts a certificate only if the bridge made it: it holds
// an Ed25519 key and its signature field is an HMAC of that key under the
// shared key. A real cover site certificate never matches.
func verifyBridgeCert(rawCerts [][]byte, authKey []byte) error {
	if len(rawCerts) == 0 {
		return ErrNotBridge
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotBridge, err)
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return ErrNotBridge
	}
	mac := hmac.New(sha512.New, authKey)
	mac.Write(pub)
	if !hmac.Equal(mac.Sum(nil), leaf.Signature) {
		return ErrNotBridge
	}
	return nil
}
