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
		"1/5 -- Set the 'Timing-Auth' header",
		"2/5 -- JWT Signing Key: " + secret,
		"3/5 -- Add a claim named 'handle' containing your discord handle to the JWT payload.",
		"4/5 -- Put the JWT in a Header called 'Jwt'",
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
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/instructions", handleInstructions)
	http.HandleFunc("/scoreboard", handleScoreboard)
	http.HandleFunc("/scoreboard/add", handleScoreboardAdd)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("Serving http: %s", err)
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	message := `
		This server, like most servers, operates thanks to the diligence of tiny green 
		elves shuffling papers about inside a bleak industrial datacenter.  Today the 
		mood is a bit brighter as they are throwing a tea party.  

		Please do be patient with them as they may be a bit slow handling your requests.
		Rest assured they will do all they can to help you on your journey as lulls in
		the party allow them. Today may be a day of leisure but they still strongly
		believe in doing things the right way, one thing following another.

		Your challenge is to follow the /instructions and add your name to the /scoreboard.  
		Your scope is this domain.`
	w.Write([]byte(message))
	log.Println("served /: ", r.RemoteAddr)
}

func handleInstructions(w http.ResponseWriter, r *http.Request) {
	if !mutex.TryLock() {
		w.WriteHeader(http.StatusTeapot)
		return
	}
	if index > 0 {
		v, ok := r.Header["Timing-Auth"]
		if !ok || !validHeader(v) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Missing or invalid 'Timing-Auth' header."))
			log.Println("invalid /instructions request: ", r.RemoteAddr)
			mutex.Unlock()
			return
		}
	}
	w.Write(buildResponseData())
	log.Println("valid /instructions request: ", r.RemoteAddr)
	mutex.Unlock()
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
	log.Println("served /scoreboard: ", r.RemoteAddr)
}

func handleScoreboardAdd(w http.ResponseWriter, r *http.Request) {
	token, ok := r.Header["Jwt"]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Did you read the '/instructions'?"))
		log.Println("invalid /scoreboard/add: ", r.RemoteAddr)
		return
	}

	username, err := getContestantUsername(token[0])
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Did you read the '/instructions'?"))
		log.Println("invalid /scoreboard/add: ", r.RemoteAddr)
		return
	}
	scoreboard[username] = time.Now().Format(time.RFC850)
	log.Println("valid /scoreboard/add: ", r.RemoteAddr)
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
