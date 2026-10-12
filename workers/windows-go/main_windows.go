package main

import (
	"io"
	"log"
	"os"
)

func main() {
	log.SetOutput(io.Discard)
	if runWorker(os.Stdin, os.Stdout) != nil {
		os.Exit(1)
	}
}
