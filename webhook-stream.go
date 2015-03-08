package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

var Version = "0.1.0"

func assert(err error, context string) {
	if err != nil {
		log.Fatal(context+": ", err)
	}
}

func getopt(name, dfault string) string {
	value := os.Getenv(name)
	if value == "" {
		value = dfault
	}
	return value
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(Version)
		os.Exit(0)
	}
	port := getopt("PORT", "8080")

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, getopt("SECRET", "no secret"))
	})

	log.Printf("webhook-stream %s serving on :%s", Version, port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
