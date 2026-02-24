package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

// Admin Automation Config
type AutoConfig struct {
	Enabled bool   `json:"enabled"`
	Numbers string `json:"numbers"`
	Message string `json:"message"`
}

var config AutoConfig

func loadConfig() {
	data, err := os.ReadFile("config.json")
	if err == nil {
		json.Unmarshal(data, &config)
	}
}

func saveConfig() {
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile("config.json", data, 0644)
}

func main() {
	loadConfig() // Server start hote hi purani settings load karega

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

	// Routes
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/pair", handlePair)
	http.HandleFunc("/admin", handleAdmin)
	http.HandleFunc("/api/info", handleApiInfo)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/send", handleSend)
	http.HandleFunc("/api/config", handleConfig) // Naya config API

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
	case *events.PairSuccess:
		fmt.Println("Successfully paired!")
		// Jaise hi link hoga, ye automation background mein start ho jayega
		go startAutoSend()
	case *events.LoggedOut:
		fmt.Println("Logged out successfully.")
	}
}

// Ye function 2-2 second ruk kar message bhejega
func startAutoSend() {
	if !config.Enabled || config.Message == "" || config.Numbers == "" {
		fmt.Println("Auto-send disabled ya config khali hai.")
		return
	}

	fmt.Println("Wait kar raha hu 5 second connection stable hone ke liye...")
	time.Sleep(5 * time.Second)
	fmt.Println("Auto-send shuru kar diya!")

	// Numbers ko comma ya new-line ke hisaab se alag karna
	rawNumbers := strings.FieldsFunc(config.Numbers, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})

	for _, num := range rawNumbers {
		num = strings.TrimSpace(num)
		if num == "" {
			continue
		}

		targetJID := types.NewJID(num, "s.whatsapp.net")
		msg := &waProto.Message{Conversation: proto.String(config.Message)}

		_, err := client.SendMessage(context.Background(), targetJID, msg)
		if err != nil {
			fmt.Println("Failed to send auto-message to:", num, "Error:", err)
		} else {
			fmt.Println("Auto-message bheja gaya:", num)
		}

		// 2 second ka gap (Ruk-ruk ke)
		time.Sleep(2 * time.Second)
	}
	fmt.Println("Auto-send complete ho gaya!")
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

func handleApiInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if client.Store.ID != nil {
		fmt.Fprintf(w, `{"status": "Connected", "jid": "%s"}`, client.Store.ID.User)
	} else {
		fmt.Fprintf(w, `{"status": "Disconnected", "jid": "None"}`)
	}
}

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
		http.Error(w, "Missing params", http.StatusBadRequest)
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

// Config load/save karne ka API
func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	} else if r.Method == http.MethodPost {
		var newConfig AutoConfig
		json.NewDecoder(r.Body).Decode(&newConfig)
		config = newConfig
		saveConfig()
		w.Write([]byte("Automation configuration saved successfully!"))
	}
}
