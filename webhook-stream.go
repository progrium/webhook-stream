package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
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
	sync.Mutex
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

func clientJoin(req *http.Request) (string, chan interface{}) {
	user, _, _ := req.BasicAuth()
	ip := req.RemoteAddr
	forwardedFor := req.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		ip = forwardedFor
	}
	portIndex := strings.LastIndex(ip, ":")
	if portIndex > 0 {
		ip = ip[:portIndex]
	}
	client := fmt.Sprintf("%s@%s%s", user, ip, req.URL.Path)
	clientsLock.Lock()
	defer clientsLock.Unlock()
	ch, exists := clients[client]
	if !exists {
		ch = make(chan interface{})
		clients[client] = ch
	}
	e := endpoint(req.URL.Path)
	e.Lock()
	defer e.Unlock()
	e.Clients = append(e.Clients, fmt.Sprintf("%s@%s", user, ip))
	return client, ch
}

func clientLeave(endpoint *Endpoint, name string) {
	clientsLock.Lock()
	defer clientsLock.Unlock()
	delete(clients, name)
	endpoint.Lock()
	defer endpoint.Unlock()
	dropClient(endpoint, name)
}

func dropClient(endpoint *Endpoint, name string) {
	var index int
	for i, c := range endpoint.Clients {
		if c == name {
			index = i
			break
		}
	}
	endpoint.Clients = append(endpoint.Clients[:index], endpoint.Clients[index+1:]...)
}

func handleDashboard(w http.ResponseWriter, req *http.Request) {
	user, pass, ok := req.BasicAuth()
	if !ok || user != dashboardUser || pass != clientSecret {
		w.Header().Set("WWW-Authenticate", `Basic realm="Dashboard"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if req.Header.Get("Upgrade") == "websocket" {
		websocket.Handler(func(conn *websocket.Conn) {
			for {
				endpointsLock.Lock()
				_, err := conn.Write(append(marshal(endpoints, true), '\n'))
				endpointsLock.Unlock()
				if err != nil {
					return
				}
				time.Sleep(1 * time.Second)
			}
			conn.Close()
		}).ServeHTTP(w, req)
		return
	}
	io.WriteString(w, `<html><body><pre></pre><script>
		l = window.location; p = l.protocol.replace("http", "ws");
		s = new WebSocket(p+"//"+l.hostname+":"+l.port+l.pathname);
		s.onmessage = function(event) {
			document.querySelector("pre").innerHTML = event.data;
		}
	</script></body></html>`)
}

func handleHookEndpoint(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "POST":
		var obj interface{}
		switch req.Header.Get("Content-Type") {
		case "application/json":
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			err = json.Unmarshal(body, &obj)
			if err != nil {
				http.Error(w, "Bad JSON", http.StatusBadRequest)
				return
			}
		case "application/x-www-form-urlencoded":
			err := req.ParseForm()
			if err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			m := make(map[string]string)
			for key, _ := range req.Form {
				m[key] = req.Form.Get(key)
			}
			obj = m
		default:
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}
		e := endpoint(req.URL.Path)
		e.Lock()
		defer e.Unlock()
		e.Posts += 1
		for _, client := range e.Clients {
			clientsLock.Lock()
			ch, exists := clients[client+req.URL.Path]
			clientsLock.Unlock()
			if !exists {
				defer dropClient(e, client)
				continue
			}
			select {
			case ch <- obj:
			case <-time.After(time.Second * 1):
				defer dropClient(e, client)
				continue
			}
		}
	case "GET":
		_, pass, ok := req.BasicAuth()
		if !ok || pass != clientSecret {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		e := endpoint(req.URL.Path)
		name, ch := clientJoin(req)
		defer clientLeave(e, name)
		if req.Header.Get("Upgrade") == "websocket" {
			websocket.Handler(func(conn *websocket.Conn) {
				for obj := range ch {
					_, err := conn.Write(append(marshal(obj, false), '\n'))
					if err != nil {
						return
					}
				}
				conn.Close()
			}).ServeHTTP(w, req)
			return
		}
		for obj := range ch {
			_, err := w.Write(append(marshal(obj, false), '\n'))
			w.(http.Flusher).Flush()
			if err != nil {
				return
			}
		}
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

func marshal(obj interface{}, indent bool) []byte {
	var bytes []byte
	var err error
	if indent {
		bytes, err = json.MarshalIndent(obj, "", "  ")
	} else {
		bytes, err = json.Marshal(obj)
	}
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
		switch req.URL.Path {
		case "/favicon.ico":
			http.NotFound(w, req)
		case "/":
			http.Redirect(w, req, "/dashboard", 301)
		case "/dashboard":
			handleDashboard(w, req)
		default:
			handleHookEndpoint(w, req)
		}
	})

	log.Printf("webhook-stream %s serving on :%s", Version, port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
