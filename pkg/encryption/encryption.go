package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/hkdf"
)

var (
	KeySize        = 32 // from Bitwarden specs
	EncryptedRegex = regexp.MustCompile("^" + encryptionType + `\.([A-Za-z0-9+/=]+)\|([A-Za-z0-9+/=]+)\|([A-Za-z0-9+/=]+)$`)
	encryptionType = "2"           // we expect "2.iv|ct|mac"
	stretchInfoEnc = []byte("enc") // from Bitwarden source code
	stretchInfoMac = []byte("mac") // from Bitwarden source code
)

func StretchKey(masterKey []byte) ([]byte, []byte, error) {
	if len(masterKey) != KeySize {
		return nil, nil, fmt.Errorf("master key must be %d bytes", KeySize)
	}

	encKey := make([]byte, KeySize)
	hkdfEnc := hkdf.Expand(sha256.New, masterKey, stretchInfoEnc)
	if _, err := hkdfEnc.Read(encKey); err != nil {
		return nil, nil, err
	}

	macKey := make([]byte, KeySize)
	hkdfMac := hkdf.Expand(sha256.New, masterKey, stretchInfoMac)
	if _, err := hkdfMac.Read(macKey); err != nil {
		return nil, nil, err
	}

	return encKey, macKey, nil
}

func Decrypt(encData string, encKey, macKey []byte) ([]byte, error) {

	parts := strings.SplitN(encData, ".", 2)
	if len(parts) != 2 || parts[0] != encryptionType {
		return nil, errors.New("invalid encryption format or version")
	}

	fields := strings.Split(parts[1], "|")
	if len(fields) != 3 {
		return nil, errors.New("expected format: iv|ciphertext|mac")
	}

	iv, err := base64.StdEncoding.DecodeString(fields[0])
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, err
	}

	mac, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return nil, err
	}

	macData := append(iv, ciphertext...)
	expectedMAC := hmac.New(sha256.New, macKey)
	expectedMAC.Write(macData)
	calculatedMac := expectedMAC.Sum(nil)

	if !hmac.Equal(mac, calculatedMac) {
		return nil, errors.New("MAC mismatch: possible tampering or wrong key")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}
	if len(data)%blockSize != 0 {
		return nil, errors.New("data is not a multiple of block size")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, errors.New("invalid padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("invalid PKCS#7 padding")
		}
	}
	return data[:len(data)-padLen], nil
}
