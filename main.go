package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"wa-linker/db" // Yeh aapka naya database package hai

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store/sqlstore"
	waLog "go.mau.fi/whatsmeow/util/log"
)

func main() {
	fmt.Println("🚀 Starting Enterprise WhatsApp SaaS...")

	// 1. Apna Naya Database Start Karein (Auto-Switch: Render/Local)
	db.InitDB()

	// 2. WhatsApp ke session ke liye purana store connect karein
	dbLog := waLog.Stdout("Database", "WARN", true)
	container, err := sqlstore.New(context.Background(), "sqlite3", "file:session.db?_foreign_keys=on", dbLog)
	if err != nil {
		log.Fatalf("Failed to connect to WhatsApp database: %v", err)
	}

	deviceStore, err := container.GetFirstDevice(context.Background())
	if err != nil {
		log.Fatalf("Failed to get device store: %v", err)
	}

	clientLog := waLog.Stdout("Client", "WARN", true)
	_ = whatsmeow.NewClient(deviceStore, clientLog) // Client ready

	// 3. Naya Enterprise API Router Setup Karein
	r := mux.NewRouter()
	
	// Test Route
	r.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "Enterprise System is Active 🚀"}`))
	}).Methods("GET")

	fmt.Println("🌐 Server running on Port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
