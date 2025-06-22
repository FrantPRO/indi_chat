package main

import (
	"flag"
	"indi_chat/internal/server"
	"log"
)

func main() {
	port := flag.String("port", "8080", "Port to listen on")
	flag.Parse()

	srv := server.NewServer()
	log.Fatal(srv.Start(*port))
}