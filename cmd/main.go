package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/santanoce/vaultwarden-database-decrypt/pkg/database"
	"github.com/santanoce/vaultwarden-database-decrypt/pkg/utils"

	"golang.org/x/term"
)

var (
	email      = flag.String("email", "", "User email")
	password   = flag.String("password", "", "User password")
	dbPath     = flag.String("dbPath", "", "Database file path")
	outputFile = flag.String("outputFile", "", "Output file path")
)

func main() {

	flag.Parse()

	if *dbPath == "" {
		*dbPath = promptInput("Enter database path: ")
		_, err := os.Stat(*dbPath)
		if err != nil {
			log.Fatalln("error finding database", err)
		}
	}

	if *email == "" {
		*email = promptInput("Enter email: ")
	}

	log.Println("getting user info")
	userInfo, err := database.GetUserInfo(*dbPath, *email)
	if err != nil {
		log.Fatalln("error getting user info:", err)
	}
	log.Printf("successfully retrieved user info")

	if *password == "" {
		*password = promptPassword("Enter password: ")
	}

	log.Println("checking password")
	hexPasswordHash, err := utils.GetHexPasswordHash(userInfo, *password)
	if err != nil {
		log.Fatalln("error getting password hash", err)
	}
	if hexPasswordHash != hex.EncodeToString(userInfo.PasswordHash) {
		log.Fatalln("generated password hash does not correspond to the stored hash in the database, maybe wrong password?")
	}
	log.Println("generated password hash corresponds to the stored hash in the database, password is correct")

	if *outputFile == "" {
		*outputFile = promptInput("Enter output file path: ")
	}

	log.Println("decrypting symmetric key")
	encKey, macKey, err := utils.DecryptSymmetricKey(userInfo, *password)
	if err != nil {
		log.Fatalln("error decrypting symmetric key:", err)
	}
	log.Printf("successfully decrypted symmetric key")

	log.Println("getting user data")
	encryptedUserData, err := database.GetUserData(*dbPath, userInfo.Uuid)
	if err != nil {
		log.Fatalln("error getting user data:", err)
	}
	log.Printf("successfully retrieved user data")

	log.Println("decrypting user data")
	decryptedUserData, err := utils.DecryptUserData(encryptedUserData, encKey, macKey)
	if err != nil {
		log.Fatalln("error decrypting user data:", err)
	}
	log.Printf("successfully decrypted user data")

	log.Println("creating output file")
	file, err := os.Create(*outputFile)
	if err != nil {
		log.Fatalln("error creating output file:", err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false) // disable HTML escaping
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(decryptedUserData); err != nil {
		log.Fatalln("error encoding json:", err)
	}
	log.Println("successfully created output file")
}

func promptInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalln("error reading input:", err)
	}
	return strings.TrimSpace(input)
}

func promptPassword(prompt string) string {
	oldState, err := term.GetState(int(syscall.Stdin))
	if err != nil {
		log.Fatalln("error getting terminal state:", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	go func() {
		<-sigs
		term.Restore(int(syscall.Stdin), oldState)
		os.Exit(1)
	}()

	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Fatalln("error reading password:", err)
	}
	return strings.TrimSpace(string(bytePassword))
}
