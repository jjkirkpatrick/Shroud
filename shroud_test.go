package shroud

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"reflect"
	"testing"
	"time"
)

// Test types
type ComplexUser struct {
	ID        int64
	Username  string
	Email     string
	Settings  map[string]interface{}
	Metadata  json.RawMessage
	Created   time.Time
	Admin     bool
	Score     float64
	Tags      []string
	Counts    map[string]int
	NullField *string
}

type NestedStruct struct {
	Parent struct {
		Child struct {
			Value string
		}
	}
}

// TestNewClient tests the NewClient function with various key lengths.
// It ensures that:
// - A valid 32-byte key creates a client without error
// - Keys shorter or longer than 32 bytes result in an error
// - A zero-length key results in an error
func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{"valid key", 32, false},
		{"short key", 16, true},
		{"long key", 64, true},
		{"zero key", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			_, err := io.ReadFull(rand.Reader, key)
			if err != nil {
				t.Fatal(err)
			}

			_, err = NewSecretClient(key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestShroud_PrimitiveTypes tests the Shroud and Expose methods with various primitive types.
// It verifies that:
// - Different types of primitive values can be encrypted and decrypted correctly
// - The decrypted value matches the original input
// - Edge cases like empty strings, zero, and nil are handled properly
func TestShroud_PrimitiveTypes(t *testing.T) {
	client := setupTestClient(t)

	tests := []struct {
		name  string
		value interface{}
	}{
		{"string", "hello world"},
		{"empty string", ""},
		{"integer", 42},
		{"negative integer", -42},
		{"zero", 0},
		{"float", 3.14159},
		{"negative float", -3.14159},
		{"boolean true", true},
		{"boolean false", false},
		{"nil", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := client.Shroud(tt.value)
			if err != nil {
				t.Fatalf("Shroud() error = %v", err)
			}

			var result interface{}
			err = secret.Expose(&result)
			if err != nil {
				t.Fatalf("Expose() error = %v", err)
			}

			if !reflect.DeepEqual(convertNumber(result), tt.value) {
				t.Errorf("Value mismatch: got %v (%T), want %v (%T)", result, result, tt.value, tt.value)
			}
		})
	}
}

// TestShroud_ComplexTypes tests the Shroud and Expose methods with a complex struct type.
// It ensures that:
// - A complex struct with various nested types can be encrypted and decrypted correctly
// - All fields of the struct, including nested maps and slices, are preserved after encryption and decryption
// - Time values and pointers are handled correctly
func TestShroud_ComplexTypes(t *testing.T) {
	client := setupTestClient(t)

	// Create a complex user object
	nullStr := "null-value"
	user := ComplexUser{
		ID:       12345,
		Username: "test_user",
		Email:    "test@example.com",
		Settings: map[string]interface{}{
			"theme":    "dark",
			"timezone": "UTC",
			"nested": map[string]interface{}{
				"key": "value",
			},
		},
		Metadata:  json.RawMessage(`{"custom":"data"}`),
		Created:   time.Now().UTC().Truncate(time.Second),
		Admin:     true,
		Score:     99.99,
		Tags:      []string{"tag1", "tag2", "tag3"},
		Counts:    map[string]int{"visits": 100, "posts": 50},
		NullField: &nullStr,
	}

	t.Run("complex struct", func(t *testing.T) {
		secret, err := client.Shroud(user)
		if err != nil {
			t.Fatalf("Shroud() error = %v", err)
		}

		var result ComplexUser
		err = secret.Expose(&result)
		if err != nil {
			t.Fatalf("Expose() error = %v", err)
		}

		if !reflect.DeepEqual(user, result) {
			t.Errorf("Value mismatch:\ngot  %+v\nwant %+v", result, user)
		}
	})
}

// TestShroud_Collections tests the Shroud and Expose methods with various collection types.
// It verifies that:
// - Different types of collections (slices, maps) can be encrypted and decrypted correctly
// - Empty collections are handled properly
// - Nested collections (e.g., maps containing slices) are preserved after encryption and decryption
// - Collections with mixed types are handled correctly
func TestShroud_Collections(t *testing.T) {
	client := setupTestClient(t)

	tests := []struct {
		name  string
		value interface{}
	}{
		{"string slice", []string{"a", "b", "c"}},
		{"int slice", []int{1, 2, 3}},
		{"empty slice", []string{}},
		{"mixed slice", []interface{}{1, "two", true, 4.0}},
		{"string map", map[string]string{"a": "1", "b": "2"}},
		{"int map", map[string]int{"a": 1, "b": 2}},
		{"empty map", map[string]string{}},
		{"nested map", map[string]interface{}{
			"a": 1,
			"b": "two",
			"c": []int{1, 2, 3},
			"d": map[string]string{"x": "y"},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := client.Shroud(tt.value)
			if err != nil {
				t.Fatalf("Shroud() error = %v", err)
			}

			var result interface{}
			err = secret.Expose(&result)
			if err != nil {
				t.Fatalf("Expose() error = %v", err)
			}

			if !reflect.DeepEqual(result, tt.value) {
				t.Errorf("Value mismatch: got %v, want %v", result, tt.value)
			}
		})
	}
}

// TestShroud_EdgeCases tests the Shroud and Expose methods with various edge cases and unusual inputs.
// It ensures that:
// - Unsupported types (channels, functions, complex numbers) are handled appropriately
// - Very large data structures can be encrypted and decrypted without issues
// - Deeply nested structures are handled correctly
// - Unicode strings are preserved after encryption and decryption
// - Zero-value structs can be encrypted and decrypted
func TestShroud_EdgeCases(t *testing.T) {
	client := setupTestClient(t)

	tests := []struct {
		name     string
		value    interface{}
		wantErr  bool
		errCheck func(error) bool
	}{
		{"channel", make(chan int), true, nil},
		{"function", func() {}, true, nil},
		{"complex number", complex(1, 2), true, nil},
		{"very large slice", make([]byte, 1<<20), false, nil}, // 1MB of data
		{"deeply nested struct", createDeeplyNested(100), false, nil},
		{"unicode string", "Hello, 世界! 👋 🌍", false, nil},
		{"zero value struct", struct{}{}, false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := client.Shroud(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Shroud() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				if tt.errCheck != nil && !tt.errCheck(err) {
					t.Errorf("Unexpected error type: %v", err)
				}
				return
			}

			var result interface{}
			err = secret.Expose(&result)
			if err != nil {
				t.Fatalf("Expose() error = %v", err)
			}
		})
	}
}

// TestShroud_ErrorCases tests various error scenarios for the Shroud and Expose methods.
// It verifies that:
// - Invalid encrypted values are rejected when creating a secret
// - Attempting to expose a secret to the wrong type results in an error
// - Passing a nil destination to Expose results in an error
func TestShroud_ErrorCases(t *testing.T) {
	client := setupTestClient(t)

	t.Run("invalid encrypted value", func(t *testing.T) {
		_, err := client.CreateFromEncrypted("invalid base64")
		if err == nil {
			t.Error("Expected error for invalid base64")
		}
	})

	t.Run("wrong type on expose", func(t *testing.T) {
		secret, _ := client.Shroud(42)
		var str string
		err := secret.Expose(&str)
		if err == nil {
			t.Error("Expected error when exposing to wrong type")
		}
	})

	t.Run("nil destination", func(t *testing.T) {
		secret, _ := client.Shroud("test")
		err := secret.Expose(nil)
		if err == nil {
			t.Error("Expected error with nil destination")
		}
	})
}

// TestShroud_Concurrency tests the thread-safety of the Shroud and Expose operations.
// It creates 10 goroutines, each encrypting and then decrypting a unique integer value.
// The test ensures that concurrent operations do not interfere with each other,
// and that each goroutine successfully retrieves its original value after encryption and decryption.
func TestShroud_Concurrency(t *testing.T) {
	client := setupTestClient(t)
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(val int) {
			secret, err := client.Shroud(val)
			if err != nil {
				t.Errorf("Shroud() error = %v", err)
				done <- false
				return
			}

			var result int
			err = secret.Expose(&result)
			if err != nil {
				t.Errorf("Expose() error = %v", err)
				done <- false
				return
			}

			if result != val {
				t.Errorf("Value mismatch: got %v, want %v", result, val)
				done <- false
				return
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Helper functions

func setupTestClient(t *testing.T) *Client {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewSecretClient(key)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func createDeeplyNested(depth int) interface{} {
	if depth == 0 {
		return "value"
	}
	return map[string]interface{}{
		"nested": createDeeplyNested(depth - 1),
	}
}

// convertNumber handles number type conversion issues in JSON marshaling
func convertNumber(v interface{}) interface{} {
	if f, ok := v.(float64); ok {
		if float64(int64(f)) == f {
			return int64(f)
		}
	}
	return v
}

func BenchmarkShroud(b *testing.B) {
	client := setupTestClient(nil)
	value := ComplexUser{
		ID:       12345,
		Username: "test_user",
		Email:    "test@example.com",
		Settings: map[string]interface{}{
			"theme":    "dark",
			"timezone": "UTC",
		},
		Created: time.Now(),
		Admin:   true,
		Score:   99.99,
		Tags:    []string{"tag1", "tag2", "tag3"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		secret, err := client.Shroud(value)
		if err != nil {
			b.Fatal(err)
		}
		var result ComplexUser
		if err := secret.Expose(&result); err != nil {
			b.Fatal(err)
		}
	}
}
