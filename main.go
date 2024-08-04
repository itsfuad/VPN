package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// KeyPair represents a WireGuard key pair
type KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// NewKeyPair generates a new WireGuard key pair
func NewKeyPair() (*KeyPair, error) {
	privateKey := [32]byte{}
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return nil, err
	}

	publicKey := Curve25519(privateKey[:])
	return &KeyPair{PrivateKey: privateKey, PublicKey: publicKey}, nil
}

// Curve25519 implements the Curve25519 key exchange algorithm
func Curve25519(privateKey []byte) [32]byte {
	var publicKey [32]byte
	var privateKeyArray [32]byte
	copy(privateKeyArray[:], privateKey)
	curve25519.ScalarBaseMult(&publicKey, &privateKeyArray)
	return publicKey
}

// WireGuardHandshake performs the WireGuard handshake
func WireGuardHandshake(localKeyPair *KeyPair, remotePublicKey []byte) ([]byte, error) {
	var sharedSecret [32]byte
	sharedSecretBytes, err := curve25519.X25519(localKeyPair.PrivateKey[:], remotePublicKey)
	if err != nil {
		return nil, err
	}
	copy(sharedSecret[:], sharedSecretBytes)

	// Generate an HMAC of the shared secret
	h := hmac.New(sha256.New, sharedSecret[:])
	h.Write(remotePublicKey)
	return h.Sum(nil), nil
}

// ChaCha20Poly1305Decrypt decrypts and verifies the ciphertext
func ChaCha20Poly1305Decrypt(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	// Create a new ChaCha20-Poly1305 AEAD instance with the given key
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Decrypt and verify the ciphertext
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func main() {
	ip := "0.0.0.0"   // Bind to all network interfaces
	port := 51820    // UDP port
	mtu := 1500      // MTU size

	localKeyPair, err := NewKeyPair()
	if err != nil {
		fmt.Println("Error generating local key pair:", err)
		return
	}

	// Generate a valid remote key pair for testing
	remoteKeyPair, err := NewKeyPair()
	if err != nil {
		fmt.Println("Error generating remote key pair:", err)
		return
	}

	remotePublicKey := remoteKeyPair.PublicKey[:]

	// Perform handshake
	sharedSecret, err := WireGuardHandshake(localKeyPair, remotePublicKey)
	if err != nil {
		fmt.Println("Error during handshake:", err)
		return
	}

	fmt.Println("Shared secret:", sharedSecret)

	// Create a UDP listener with the given IP and port
	addr := &net.UDPAddr{
		IP:   net.ParseIP(ip),
		Port: port,
	}
	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Error creating UDP listener:", err)
		return
	}
	defer listener.Close()

	fmt.Printf("Listening on %s:%d\n", ip, port)

	// Handle incoming UDP packets
	for {
		packet := make([]byte, mtu)
		n, _, err := listener.ReadFromUDP(packet)
		if err != nil {
			fmt.Println("Error reading from UDP:", err)
			continue
		}

		// Ensure the packet is long enough to extract nonce and ciphertext
		if n < 12 {
			fmt.Println("Packet too short")
			continue
		}

		// Extract nonce and ciphertext
		nonce := packet[:12]
		ciphertext := packet[12:n]

		// Decrypt and authenticate the packet
		plaintext, err := ChaCha20Poly1305Decrypt(sharedSecret, nonce, ciphertext)
		if err != nil {
			fmt.Println("Decryption failed:", err)
			continue
		}

		// Handle the decrypted packet
		fmt.Println("Decrypted packet:", string(plaintext))
	}
}