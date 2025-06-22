package main

import (
	"flag"
	"fmt"
	"indi_chat/internal/client"
	"log"
	"os"
)

func main() {
	name := flag.String("name", "", "Your chat name")
	server := flag.String("server", "localhost:8080", "Server address")
	flag.Parse()

	if *name == "" {
		fmt.Println("Usage: client -name <your_name> [-server <address>]")
		os.Exit(1)
	}

	c, err := client.NewClient(*name)
	if err != nil {
		log.Fatal(err)
	}

	if err := c.Connect(*server); err != nil {
		log.Fatal(err)
	}

	c.StartChat()
}