package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"code.google.com/p/go.net/websocket"
)

var Version = "0.1.0"

var (
	dashboardUser = "admin"
	clientSecret  = ""

	endpoints     = make(map[string]*Endpoint)
	endpointsLock sync.Mutex

	clients     = make(map[string]chan interface{})
	clientsLock sync.Mutex
)

type Endpoint struct {
	mu   sync.Mutex
	path string

	Posts   uint64   `json:"posts"`
	Clients []string `json:"clients"`
}

func endpoint(path string) *Endpoint {
	endpointsLock.Lock()
	defer endpointsLock.Unlock()
	e, exists := endpoints[path]
	if !exists {
		e = &Endpoint{path: path}
		endpoints[path] = e
	}
	return e
}

func client(req *http.Request) (string, chan interface{}) {
	user, _, _ := req.BasicAuth()
	ip := req.RemoteAddr
	forwardedFor := req.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		ip = forwardedFor
	}
	client := fmt.Sprintf("%s@%s", user, ip)
	clientsLock.Lock()
	defer clientsLock.Unlock()
	ch, exists := clients[client]
	if !exists {
		ch = make(chan interface{})
		clients[client] = ch
	}
	return client, ch
}

func handleDashboard(w http.ResponseWriter, req *http.Request) {
	user, pass, ok := req.BasicAuth()
	if !ok || user != dashboardUser || pass != clientSecret {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	io.WriteString(w, `<html><body><main></main><script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script></body></html>`)
}

func handleHookEndpoint(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "POST":
		// create object
		// get endpoint
		// iterate over clients
		// drop closed clients
		// return ok
	case "GET":
		_, pass, ok := req.BasicAuth()
		if !ok || pass != clientSecret {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		//_, ch := client(req)
		if req.Header.Get("Upgrade") == "websocket" {
			websocket.Handler(func(conn *websocket.Conn) {
				//for obj := range ch {
				for {
					obj := &map[string]string{"Hello": "World"}
					_, err := conn.Write(append(marshal(obj), '\n'))
					if err != nil {
						return
					}
					time.Sleep(3 * time.Second)
				}
				conn.Close()
			}).ServeHTTP(w, req)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getopt(name, dfault string) string {
	value := os.Getenv(name)
	if value == "" {
		value = dfault
	}
	return value
}

func marshal(obj interface{}) []byte {
	bytes, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		log.Println("marshal:", err)
	}
	return bytes
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(Version)
		os.Exit(0)
	}
	port := getopt("PORT", "8080")
	dashboardUser = getopt("DASHBOARD_USER", dashboardUser)
	clientSecret = getopt("CLIENT_SECRET", "")
	if clientSecret == "" {
		fmt.Println("CLIENT_SECRET must be set.")
		os.Exit(2)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.RequestURI == "/" {
			http.Redirect(w, req, "/dashboard", 301)
			return
		}
		if req.RequestURI == "/dashboard" {
			handleDashboard(w, req)
			return
		}
		handleHookEndpoint(w, req)
	})

	log.Printf("webhook-stream %s serving on :%s", Version, port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
