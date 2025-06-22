package database

import (
	"encoding/json"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

var (
	sqlDriver = "sqlite3"
)

type UserInfo struct {
	Uuid          string `db:"uuid"`
	Email         string `db:"email"`
	AKey          string `db:"akey"`
	ClientKdfIter int    `db:"client_kdf_iter"`
	PasswordHash  []byte `db:"password_hash"`
	PasswordIter  int    `db:"password_iterations"`
	PasswordSalt  []byte `db:"salt"`
}

func GetUserInfo(dbPath, email string) (UserInfo, error) {
	db, err := sqlx.Open(sqlDriver, dbPath)
	if err != nil {
		return UserInfo{}, err
	}
	defer db.Close()

	var user UserInfo
	err = db.Get(&user, "SELECT uuid, email, akey, client_kdf_iter, password_hash, password_iterations, salt FROM users WHERE email = ?", email)
	if err != nil {
		return UserInfo{}, err
	}

	return user, nil
}

type DecryptedUserData struct {
	Name   string          `json:"name"`
	Data   json.RawMessage `json:"data"`
	Fields json.RawMessage `json:"fields"`
}

type EncryptedUserData struct {
	Name   string `db:"name"`
	Data   []byte `db:"data"`
	Fields []byte `db:"fields"`
}

func GetUserData(dbPath, userUuid string) ([]EncryptedUserData, error) {
	db, err := sqlx.Open(sqlDriver, dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var userData []EncryptedUserData
	err = db.Select(&userData, "SELECT name, data, fields FROM ciphers WHERE user_uuid = ?", userUuid)
	if err != nil {
		return nil, err
	}

	return userData, nil
}
