package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waProto "go.mau.fi/whatsmeow/proto/waE2E"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

var client *whatsmeow.Client

func main() {
	dbLog := waLog.Stdout("Database", "WARN", true)
	container, err := sqlstore.New(context.Background(), "sqlite3", "file:session.db?_foreign_keys=on", dbLog)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	deviceStore, err := container.GetFirstDevice(context.Background())
	if err != nil {
		log.Fatalf("Failed to get device store: %v", err)
	}

	clientLog := waLog.Stdout("Client", "WARN", true)
	client = whatsmeow.NewClient(deviceStore, clientLog)
	client.AddEventHandler(eventHandler)

	// User Routes
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/pair", handlePair)
	
	// Admin & API Routes
	http.HandleFunc("/admin", handleAdmin)
	http.HandleFunc("/api/info", handleApiInfo)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/send", handleSend)

	fmt.Println("Server running on http://localhost:8080")
	fmt.Println("Admin panel available at http://localhost:8080/admin")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func eventHandler(evt interface{}) {
	switch v := evt.(type) {
	case *events.Message:
		fmt.Println("Received message from:", v.Info.Sender.User)
	case *events.Connected:
		fmt.Println("Connected to WhatsApp WebSocket.")
	case *events.LoggedOut:
		fmt.Println("Logged out successfully.")
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "admin.html")
}

func handlePair(w http.ResponseWriter, r *http.Request) {
	phone := r.URL.Query().Get("phone")
	if phone == "" {
		http.Error(w, "Phone number is required", http.StatusBadRequest)
		return
	}

	if client.Store.ID != nil {
		w.Write([]byte("Already Linked"))
		return
	}

	if !client.IsConnected() {
		client.Connect()
	}

	code, err := client.PairPhone(r.Context(), phone, true, whatsmeow.PairClientChrome, "Chrome (Linux)")
	if err != nil {
		http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(code))
}

// API to check status for Admin Panel
func handleApiInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if client.Store.ID != nil {
		fmt.Fprintf(w, `{"status": "Connected", "jid": "%s"}`, client.Store.ID.User)
	} else {
		fmt.Fprintf(w, `{"status": "Disconnected", "jid": "None"}`)
	}
}

// API to Logout remotely
func handleLogout(w http.ResponseWriter, r *http.Request) {
	if client.Store.ID != nil {
		err := client.Logout(context.Background())
		if err != nil {
			http.Error(w, "Failed to logout", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Logged out successfully"))
	} else {
		w.Write([]byte("Not logged in"))
	}
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	targetPhone := r.URL.Query().Get("phone")
	msgText := r.URL.Query().Get("text")

	if targetPhone == "" || msgText == "" {
		http.Error(w, "Missing phone or text", http.StatusBadRequest)
		return
	}

	targetJID := types.NewJID(targetPhone, "s.whatsapp.net")
	msg := &waProto.Message{Conversation: proto.String(msgText)}

	_, err := client.SendMessage(context.Background(), targetJID, msg)
	if err != nil {
		http.Error(w, "Send failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("Success"))
}
