package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func initServer(t *testing.T) error {
    if err := startServer(); err != nil {
        t.Errorf("Error starting server: %v", err)
    }
    return nil
}

func TestVPNServer(t *testing.T) {
    // Define server address and port
    serverAddr := "localhost:51820"

    // Start the VPN server in a separate goroutine
    go initServer(t)

    // Wait for the server to start
    time.Sleep(2 * time.Second)

    // Define the shared secret, nonce, and test data
    key := make([]byte, 32) // Replace with the actual shared secret
    nonce := make([]byte, 12)
    _, err := rand.Read(nonce)
    if err != nil {
        t.Fatalf("Error generating nonce: %v", err)
    }

    aead, err := chacha20poly1305.New(key)
    if err != nil {
        t.Fatalf("Error creating AEAD: %v", err)
    }

    plaintext := []byte("test data")
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    // Send test data to the VPN server
    conn, err := net.Dial("udp", serverAddr)
    if err != nil {
        t.Fatalf("Error connecting to server: %v", err)
    }
    defer conn.Close()

    _, err = conn.Write(append(nonce, ciphertext...))
    if err != nil {
        t.Fatalf("Error sending data: %v", err)
    }
}

func startServer() error {
    // Create a UDP listener
    listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 51820})
    if err != nil {
        return err
    }
    defer listener.Close()

    // Handle incoming UDP packets
    for {
        packet := make([]byte, 1024)
        n, _, err := listener.ReadFromUDP(packet)
        if err != nil {
            return err
        }

        // Assume the first 12 bytes are the nonce
        nonce := packet[:12]
        ciphertext := packet[12:n]

        // Decrypt and authenticate the packet
        key := make([]byte, 32) // Replace with the actual shared secret
        plaintext, err := ChaCha20Poly1305Decrypt(key, nonce, ciphertext)
        if err != nil {
            continue
        }

        // Print decrypted packet
        fmt.Println("Decrypted packet:", plaintext)
    }
}