package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/philippseith/signalr"
	"golang.org/x/net/context"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type AppHub struct {
	signalr.Hub
}

var (
	hub              = AppHub{}
	secretKey string = ""
)

func main() {
	events := make(chan string)
	router := http.NewServeMux()
	secretKey = os.Getenv("SECRET_KEY")
	if len(secretKey) != 32 {
		log.Fatal("SECRET_KEY must be 32 characters long")
	}

	router.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		var writer = strings.Builder{}

		writer.Write([]byte(r.Method + " " + r.URL.Path + " " + r.Proto + "\n"))
		r.Header.Write(&writer)
		writer.Write([]byte("\n"))

		// Read all content from reader
		b, err := io.ReadAll(r.Body)
		if err != nil {
			log.Fatal("Error reading body. ", err)
		}
		writer.Write(b)

		events <- writer.String()

		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	router.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		for {
			s := <-events
			s = encrypt(s)
			s = base64.URLEncoding.EncodeToString([]byte(s))

			fmt.Fprintf(w, "data: %v\n\n", s)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	})

	// build a signalr.Server using your hub
	// and any server options you may need
	server, _ := signalr.NewServer(
		context.TODO(),
		signalr.SimpleHubFactory(hub),
		signalr.KeepAliveInterval(2*time.Second),
		nil)

	server.MapHTTP(signalr.WithHTTPServeMux(router), "/signalr")

	go func() {
		for {
			s := <-events
			s = encrypt(s)
			s = base64.URLEncoding.EncodeToString([]byte(s))
			server.HubClients().All().Send("ReceiveMessage", s)
			log.Println("Message received!")
		}
	}()

	log.Print("Listening on http://localhost:3333/webhook and http://localhost:3333/sse")

	if err := http.ListenAndServe(":3333", router); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}

func (c AppHub) Initialize(hubContext signalr.HubContext) {
	fmt.Println("Hub initialized")
}

func (c AppHub) OnConnected(connectionID string) {
	fmt.Printf("%s connected\n", connectionID)
}

func (c AppHub) OnDisconnected(connectionID string) {
	fmt.Printf("%s disconnected\n", connectionID)
}

func encrypt(plaintext string) string {
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	// We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	// ciphertext here is actually nonce+ciphertext
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return string(ciphertext)
}
