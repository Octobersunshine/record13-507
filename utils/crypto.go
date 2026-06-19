package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

func AesEncrypt(plainText string, key string) (string, error) {
	byteKey := []byte(key)
	if len(byteKey) != 32 {
		return "", errors.New("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(byteKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func AesDecrypt(cipherText string, key string) (string, error) {
	byteKey := []byte(key)
	if len(byteKey) != 32 {
		return "", errors.New("key must be 32 bytes for AES-256")
	}

	rawCipherText, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(byteKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(rawCipherText) < nonceSize {
		return "", errors.New("invalid cipher text")
	}

	nonce, rawCipherText := rawCipherText[:nonceSize], rawCipherText[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, rawCipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
