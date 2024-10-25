package main

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/jjkirkpatrick/shroud"
)

func main() {
	// Generate a random 32-byte key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	// Create a new client
	client, err := shroud.NewSecretClient(key)
	if err != nil {
		panic(err)
	}

	// Example with string
	stringSecret, err := client.Shroud("my-sensitive-data")
	if err != nil {
		panic(err)
	}

	var exposedString string
	if err := stringSecret.Expose(&exposedString); err != nil {
		panic(err)
	}
	fmt.Printf("String value: %s\n", exposedString)

	// Example with struct
	type User struct {
		Username string
		ApiKey   string
	}

	user := User{
		Username: "john_doe",
		ApiKey:   "secret-api-key",
	}

	structSecret, err := client.Shroud(user)
	if err != nil {
		panic(err)
	}

	// Store this encrypted value
	encryptedValue := structSecret.EncryptedValue()
	fmt.Printf("Encrypted value: %s\n", encryptedValue)

	// Later, recreate the secret from the stored encrypted value
	retrievedSecret, err := client.CreateFromEncrypted(encryptedValue)
	if err != nil {
		panic(err)
	}

	// Expose the original value into a new User struct
	var retrievedUser User
	if err := retrievedSecret.Expose(&retrievedUser); err != nil {
		panic(err)
	}

	fmt.Printf("Retrieved user: %+v\n", retrievedUser)

}
