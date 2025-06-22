package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"

	"github.com/santanoce/vaultwarden-database-decrypt/pkg/database"
	"github.com/santanoce/vaultwarden-database-decrypt/pkg/encryption"

	"golang.org/x/crypto/pbkdf2"
)

func GetHexPasswordHash(userInfo database.UserInfo, password string) (string, error) {
	masterKey := pbkdf2.Key([]byte(password), []byte(userInfo.Email), userInfo.ClientKdfIter, encryption.KeySize, sha256.New)

	masterPasswordHash := pbkdf2.Key(masterKey, []byte(password), 1, encryption.KeySize, sha256.New)

	mpHashBs64 := base64.StdEncoding.EncodeToString(masterPasswordHash)

	finalHash := pbkdf2.Key([]byte(mpHashBs64), userInfo.PasswordSalt, userInfo.PasswordIter, encryption.KeySize, sha256.New)

	return hex.EncodeToString(finalHash), nil
}

func DecryptSymmetricKey(userInfo database.UserInfo, password string) ([]byte, []byte, error) {
	masterKey := pbkdf2.Key([]byte(password), []byte(userInfo.Email), userInfo.ClientKdfIter, encryption.KeySize, sha256.New)

	masterKeyEnc, masterKeyMac, err := encryption.StretchKey(masterKey)
	if err != nil {
		return nil, nil, err
	}

	symKey, err := encryption.Decrypt(userInfo.AKey, masterKeyEnc, masterKeyMac)
	if err != nil {
		return nil, nil, err
	}

	encKey := symKey[:encryption.KeySize]
	macKey := symKey[encryption.KeySize:]

	return encKey, macKey, nil
}

func DecryptUserData(encryptedUserData []database.EncryptedUserData, encKey []byte, macKey []byte) ([]database.DecryptedUserData, error) {
	decryptedUserData := make([]database.DecryptedUserData, len(encryptedUserData))

	for i, userElement := range encryptedUserData {
		elementName, err := encryption.Decrypt(userElement.Name, encKey, macKey)
		if err != nil {
			return nil, err
		}
		decryptedUserData[i].Name = string(elementName)

		// Decrypt data
		if userElement.Data != nil {
			var dataParsed map[string]any
			if err := json.Unmarshal([]byte(userElement.Data), &dataParsed); err != nil {
				return nil, err
			}

			decryptedData, err := decryptElement(dataParsed, encKey, macKey)
			if err != nil {
				return nil, err
			}

			var buf bytes.Buffer
			encoder := json.NewEncoder(&buf)
			encoder.SetEscapeHTML(false) // disable HTML escaping

			if err := encoder.Encode(decryptedData); err != nil {
				return nil, err
			}

			decryptedUserData[i].Data = buf.Bytes()
		}

		// Decrypt fields
		if userElement.Fields != nil {
			var fieldsParsed []map[string]any
			if err := json.Unmarshal([]byte(userElement.Fields), &fieldsParsed); err != nil {
				return nil, err
			}

			decryptedFields := make([]map[string]any, len(fieldsParsed))
			for i, field := range fieldsParsed {
				decryptedField, err := decryptElement(field, encKey, macKey)
				if err != nil {
					return nil, err
				}
				decryptedFields[i] = decryptedField
			}

			var buf bytes.Buffer
			encoder := json.NewEncoder(&buf)
			encoder.SetEscapeHTML(false) // disable HTML escaping

			if err := encoder.Encode(decryptedFields); err != nil {
				return nil, err
			}

			decryptedUserData[i].Fields = buf.Bytes()
		}

	}

	return decryptedUserData, nil
}

func decryptElement(encryptedData map[string]any, encKey []byte, macKey []byte) (map[string]any, error) {
	decryptedData := make(map[string]any)

	maps.Copy(decryptedData, encryptedData)

	for keyEncryptedData, untypedValueEncryptedData := range encryptedData {
		switch typedValueEncryptedData := untypedValueEncryptedData.(type) {

		case string:
			if encryption.EncryptedRegex.Match([]byte(typedValueEncryptedData)) {
				plainData, err := encryption.Decrypt(typedValueEncryptedData, encKey, macKey)
				if err != nil {
					return nil, err
				}
				decryptedData[keyEncryptedData] = string(plainData)
			}

		case []any: // for fields like "uris" and "fido2Credentials"
			for _, untypedValue := range typedValueEncryptedData {
				switch typedValue := untypedValue.(type) {
				case map[string]any:
					for keyMap, untypedValueMap := range typedValue {
						switch typedValueMap := untypedValueMap.(type) {
						case string:
							if encryption.EncryptedRegex.Match([]byte(typedValueMap)) {
								plainData, err := encryption.Decrypt(typedValueMap, encKey, macKey)
								if err != nil {
									return nil, err
								}
								typedValue[keyMap] = string(plainData)
							}
						}
					}
				}
			}

		}
	}

	return decryptedData, nil
}
