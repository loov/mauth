package main

import "crypto/rand"

// secretWithFallback returns []byte(s) or random bytes when s is empty.
func secretWithFallback(s string) []byte {
	if s != "" {
		return []byte(s)
	}

	var data [64]byte
	_, err := rand.Read(data[:])
	if err != nil {
		panic("random is broken: " + err.Error())
	}

	return data[:]
}
