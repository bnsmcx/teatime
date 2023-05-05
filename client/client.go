package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type cData struct {
	InstructionFragment string `json:"instruction_fragment"`
	NextAuthHeader      string `json:"next_auth_header"`
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}
	switch os.Args[1] {
	case "--get-instructions":
		getInstructions()
	case "--scoreboard":
		if len(os.Args) < 4 {
			printHelp()
			return
		}
		submitToScoreboard()
	default:
		printHelp()
	}
}

func submitToScoreboard() {
	username := os.Args[2]
	secret := os.Args[3]
	payload := map[string]string{
		"handle": username,
	}
	token, err := generateJWT(payload, secret)
	if err != nil {
		fmt.Println(err)
	}

	var url = "http://localhost:8000"
	req, err := http.NewRequest("GET", url+"/scoreboard/add", nil)
	if err != nil {
		fmt.Println(err)
	}
	req.Header.Add("jwt", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		fmt.Println(resp.Status)
		fmt.Println(string(data))
		return
	}
	fmt.Println("Added to scoreboard")
}

func generateJWT(payload map[string]string, secret string) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signature := createSignature(encodedHeader, encodedPayload, secret)

	return fmt.Sprintf("%s.%s.%s", encodedHeader, encodedPayload, signature), nil
}

func createSignature(encodedHeader string, encodedPayload string, secret string) string {
	data := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(data))
	signature := hash.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(signature)
}

func getInstructions() {
	var url = "http://localhost:8000"
	var data cData
	for {
		time.Sleep(time.Second)
		req, err := http.NewRequest("GET", url+"/instructions", nil)
		req.Header.Add("timing-auth", data.NextAuthHeader)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			fmt.Println(resp.Status)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			continue
		}
		err = json.Unmarshal(body, &data)
		if err != nil {
			fmt.Println(err)
			continue
		}

		fmt.Println(data.InstructionFragment)
	}
}

func printHelp() {
	fmt.Println("\nUsage:")
	fmt.Println("\n--get-instructions")
	fmt.Println("\tcontinuously get and print instruction fragments")
	fmt.Println("--scoreboard")
	fmt.Println("\tsubmit username to scoreboard")
	fmt.Println("\t$ --scoreboard <username> <jwt-secret-key>")
}
