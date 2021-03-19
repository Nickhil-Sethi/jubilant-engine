package main

import "time"

type Secret struct {
	FileName  string
	Encrypted bool
	Key       string
	TTL       time.Duration
}

func (s *Secret) Read() (string, Error) {
	return nil
}

func (s *Secret) Write(plaintext string) Error {
	return nil
}

func (s *Secret) encrypt(plaintext string) (string, Error) {
	return "", nil
}

func (s *Secret) decrypt(cyphertext string) Error {
	return "", nil
}
