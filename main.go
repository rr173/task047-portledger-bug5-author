// Command task047-portledger runs the host port inventory and change detection
// service.
//
// Start the HTTP server with `-addr :8080`. Use `-smoke-test` to run the
// built-in self-check, which exits the process on completion.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"task047-portledger/internal/api"
	"task047-portledger/internal/registry"
	"task047-portledger/internal/selfcheck"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	smoke := flag.Bool("smoke-test", false, "run the built-in self-check and exit")
	flag.Parse()

	if *smoke {
		if err := selfcheck.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "smoke-test FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("smoke-test PASSED")
		return
	}

	mux := api.New(registry.New())
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("port ledger listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}
