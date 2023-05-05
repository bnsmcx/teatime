package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const secret = "Q3JlZXBpbmcgRGVhdGgK"

var (
	mutex        sync.Mutex
	index        int
	scoreboard   = make(map[string]string, 0)
	instructions = [...]string{
		"1/5 -- JWT Signing Key:",
		"2/5 -- " + secret,
		"3/5 -- Add a claim named 'handle' containing your discord handle to the JWT payload.",
		"4/5 -- Put the JWT in a Header called 'jwt'",
		"5/5 -- Scoreboard endpoint: /scoreboard/add",
	}
)

type Data struct {
	InstructionFragment string `json:"instruction_fragment"`
	NextAuthHeader      string `json:"next_auth_header"`
}

func main() {
	// Start the timing service
	go timingService(&mutex, &index)

	// Setup the server
	http.HandleFunc("/instructions", handleInstructions)
	http.HandleFunc("/scoreboard", handleScoreboard)
	http.HandleFunc("/scoreboard/add", handleScoreboardAdd)

	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		log.Fatalf("Serving http: %s", err)
	}
}

func handleScoreboardAdd(w http.ResponseWriter, r *http.Request) {
	token, ok := r.Header["Jwt"]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Did you read the '/instructions'?"))
		return
	}

	username, err := getContestantUsername(token[0])
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Did you read the '/instructions'?"))
		return
	}
	scoreboard[username] = time.Now().Format(time.RFC850)
}

func getContestantUsername(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid token format")
	}

	encodedHeader, encodedPayload, signature := parts[0], parts[1], parts[2]

	// Verify the JWT signature
	if !verifySignature(encodedHeader, encodedPayload, signature, secret) {
		return "", errors.New("invalid signature")
	}

	// Decode the JWT payload
	payload, err := decodePayload(encodedPayload)
	if err != nil {
		return "", err
	}

	// Validate the claims in the payload
	name, ok := payload["handle"]
	if !ok || len(name) < 1 {
		return "", errors.New("missing contestant's handle")
	}

	return name, nil
}

func decodePayload(encodedPayload string) (map[string]string, error) {
	payloadJSON, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, errors.New("invalid payload encoding")
	}

	var payload map[string]string
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, errors.New("invalid payload format")
	}

	return payload, nil
}

func verifySignature(encodedHeader, encodedPayload, signature, secret string) bool {
	expectedSignature := createSignature(encodedHeader, encodedPayload, secret)
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

func createSignature(encodedHeader string, encodedPayload string, secret string) string {
	data := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(data))
	signature := hash.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(signature)
}

func handleScoreboard(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("SCOREBOARD\n"))
	if len(scoreboard) < 1 {
		w.Write([]byte("\nNobody has solved the challenge yet."))
	}
	for k, v := range scoreboard {
		entry := fmt.Sprintf("%s - %s\n", k, v)
		w.Write([]byte("\n" + entry))
	}
}

func handleInstructions(w http.ResponseWriter, r *http.Request) {
	if !mutex.TryLock() {
		w.WriteHeader(http.StatusTeapot)
		return
	}
	if index > 0 {
		v, ok := r.Header["Timing-Auth"]
		if !ok || !validHeader(v) {
			fmt.Println(v, ok)
			w.WriteHeader(http.StatusUnauthorized)
			mutex.Unlock()
			return
		}
	}
	w.Write(buildResponseData())
	mutex.Unlock()
}

func validHeader(headers []string) bool {
	for _, token := range headers {
		if token == fmt.Sprintf("%x", sha256.Sum256([]byte(instructions[index-1]))) {
			return true
		}
	}
	return false
}

func buildResponseData() []byte {
	data := Data{
		InstructionFragment: instructions[index],
		NextAuthHeader:      fmt.Sprintf("%x", sha256.Sum256([]byte(instructions[index]))),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("building response: %s", err)
	}
	return jsonData
}

func timingService(s *sync.Mutex, index *int) {
	startingInterval := 60 / len(instructions)
	for {
		currentInterval := startingInterval
		for i := range instructions {
			s.Lock()
			*index = i
			time.Sleep(time.Duration(currentInterval) * time.Second)
			s.Unlock()
			time.Sleep(time.Second)

			if i == 0 {
				continue
			} else if i >= currentInterval {
				currentInterval = 1
			} else {
				currentInterval /= i + 1
			}
		}
	}
}

// Only accept requests during 1 second intervals that open on a decay cycle

// A part of the instructions can be GET requested at each interval

// Each GET returns a key needed for the next GET

// Instructions are base64 encoded

// Once decrypted they contain a JWT signing key and the scoreboard route

// User passes their discord handle as a claim in JWT signed by correct key
