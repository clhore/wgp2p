package wgkeys

import (
	"crypto/rand"
	"encoding/base64"
)

func GeneratePrivateKey() string {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic("Error generando la clave privada")
	}
	return base64.StdEncoding.EncodeToString(key)
}

func GeneratePublicKey(privateKey string) string {
	key, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		panic("Error decodificando la clave privada")
	}
	publicKey := make([]byte, 32)
	copy(publicKey, key[:32])
	return base64.StdEncoding.EncodeToString(publicKey)
}
