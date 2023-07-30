package cryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rc4"
	"errors"
	"io"
	"log"
	"strconv"
)

func Xor(key string, shellCode []byte) []byte {
	for i := 0; i < len(shellCode); i++ {
		shellCode[i] = shellCode[i] ^ key[i%len(key)]
	}
	return shellCode
}

func Rot(key string, shellCode []byte) []byte {
	rot, err := strconv.Atoi(key)
	if err != nil {
		log.Fatal("[x] Error: ROT encryption requires the key to consist of digits only.")
	}
	for i := 0; i < len(shellCode); i++ {
		shellCode[i] = shellCode[i] + byte(rot)
	}
	return shellCode
}

func Aes256(key, data []byte) ([]byte, []byte, error) {
	if !isValidAESKey(key) {
		return nil, nil, errors.New("[x] Error: AES key length does not match the requirements. It should be 16, 24, or 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	data = pad(data)
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

	return ciphertext[aes.BlockSize:], iv, nil
}
func isValidAESKey(key []byte) bool {
	length := len(key)
	return length == 16 || length == 24 || length == 32
}
func pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padBytes := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padBytes...)
}

func Rc4(key, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(data))
	c.XORKeyStream(dst, data)
	return dst, nil
}
