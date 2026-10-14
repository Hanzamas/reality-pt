// Command reality-keygen prints a fresh key pair and short ID for a bridge.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/hanzamas/reality-pt/transport/reality"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "reality-keygen:", err)
		os.Exit(1)
	}
}

func run() error {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var id reality.ShortID
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	fmt.Printf("private-key: %s\n", reality.EncodeKey(priv.Bytes()))
	fmt.Printf("public-key:  %s\n", reality.EncodeKey(priv.PublicKey().Bytes()))
	fmt.Printf("short-id:    %s\n", id)
	return nil
}
