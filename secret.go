package main

import "time"

type Secret struct {
	FileName  string
	Encrypted bool
	Key       string
	TTL       time.Duration
}

func (s *Secret) Read() (string, error) {
	var filecontent []byte
	var err Error

	filecontent, err := ioutil.ReadFile(s.FileName)
	if err != nil {
		return nil, err
	}

	if s.Encrypted {
		filecontent, err = s.decrypt(filecontent)
		if err != nil {
			return nil, err
		}
	}
	return filecontent, nil

}

func (s *Secret) Write(plaintext string) Error {
	var filecontent string = plaintext
	if s.Encrypted {
		filecontent = s.encrypt(plaintext)
	}
	return ioutil.WriteFile(s.Filename, filecontent, 0777)
}

func (s *Secret) encrypt(plaintext string) (string, Error) {
	block, err := s.getKey()
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of repeat.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return return ciphertext, nil
}

func (s *Secret) decrypt(ciphertext string) (string, Error) {
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (s *Secret) getKey() (string, Error) {
	key, err := ioutil.ReadFile("key")
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	return block, err
}
