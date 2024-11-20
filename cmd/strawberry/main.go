package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
)

func main() {
	globalState := &state.State{}
	mu := &sync.RWMutex{}

	// a simple http server that demonstrates the block import capabilities
	// this will be replaced with proper p2p network communication in milestone 2
	mux := http.NewServeMux()
	mux.HandleFunc("/block/import", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		newBlock := block.Block{}
		if err := json.NewDecoder(r.Body).Decode(&newBlock); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		if err := statetransition.UpdateState(globalState, newBlock); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := json.NewEncoder(w).Encode(map[string]string{"status": "success"}); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	log.Println("demo server running on port :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func jsonError(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "error",
		"message": message,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
