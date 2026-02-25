main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
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

// System Logs Memory (Live Terminal ke liye)
var systemLogs []string
var logMu sync.Mutex

func addLog(msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	timestamp := time.Now().Format("15:04:05")
	logEntry := fmt.Sprintf("[%s] %s", timestamp, msg)
	systemLogs = append([]string{logEntry}, systemLogs...)
	if len(systemLogs) > 50 { // Sirf latest 50 logs rakhega memory bachane ke liye
		systemLogs = systemLogs[:50]
	}
	fmt.Println(logEntry) // Termux me bhi print karega
}

type AutoConfig struct {
	Enabled     bool   `json:"enabled"`
	Numbers     string `json:"numbers"`
	Message     string `json:"message"`
	ReplyEnable bool   `json:"reply_enable"`
	ReplyText   string `json:"reply_text"`
}
var config AutoConfig

func loadConfig() {
	data, err := os.ReadFile("config.json")
	if err == nil { json.Unmarshal(data, &config) }
}
func saveConfig() {
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile("config.json", data, 0644)
}

// Security Middleware (Server-Side Password)
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		// Apna Admin Username aur Password yahan set karein 👇
		if !ok || user != "admin" || pass != "admin123" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Area"`)
			http.Error(w, "Unauthorized Access", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func main() {
	loadConfig()
	addLog("🚀 Server started successfully!")

	dbLog := waLog.Stdout("Database", "WARN", true)
	container, err := sqlstore.New(context.Background(), "sqlite3", "file:session.db?_foreign_keys=on", dbLog)
	if err != nil { log.Fatalf("Failed to connect to database: %v", err) }

	deviceStore, err := container.GetFirstDevice(context.Background())
	if err != nil { log.Fatalf("Failed to get device store: %v", err) }

	clientLog := waLog.Stdout("Client", "WARN", true)
	client = whatsmeow.NewClient(deviceStore, clientLog)
	client.AddEventHandler(eventHandler)

	// Public Routes (Bina Password)
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/pair", handlePair)
	http.HandleFunc("/is-linked", handleIsLinked) 

	// Secure Admin Routes (Password Required)
	http.HandleFunc("/admin", basicAuth(handleAdmin))
	http.HandleFunc("/api/info", basicAuth(handleApiInfo))
	http.HandleFunc("/api/config", basicAuth(handleConfig))
	http.HandleFunc("/api/logs", basicAuth(handleLogs))
	http.HandleFunc("/logout", basicAuth(handleLogout))
	http.HandleFunc("/send", basicAuth(handleSend))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func eventHandler(evt interface{}) {
	switch v := evt.(type) {
	case *events.Message:
		if !v.Info.IsFromMe {
			addLog(fmt.Sprintf("📩 Message received from: %s", v.Info.Sender.User))
			if !v.Info.IsGroup && config.ReplyEnable && config.ReplyText != "" {
				addLog("🤖 Sending Auto-Reply to: " + v.Info.Sender.User)
				msg := &waProto.Message{Conversation: proto.String(config.ReplyText)}
				client.SendMessage(context.Background(), v.Info.Sender, msg)
			}
		}
	case *events.Connected:
		addLog("🟢 Connected to WhatsApp Server")
	case *events.PairSuccess:
		addLog("✅ Device Successfully Linked!")
		go startAutoSend()
	case *events.LoggedOut:
		addLog("🔴 Device Logged Out")
	}
}

func startAutoSend() {
	if !config.Enabled || config.Message == "" || config.Numbers == "" { return }
	addLog("⏳ Waiting 5 seconds before Auto-Send...")
	time.Sleep(5 * time.Second)
	addLog("🚀 Starting Auto-Send to numbers!")
	
	rawNumbers := strings.FieldsFunc(config.Numbers, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	for _, num := range rawNumbers {
		num = strings.TrimSpace(num)
		if num == "" { continue }
		targetJID := types.NewJID(num, "s.whatsapp.net")
		msg := &waProto.Message{Conversation: proto.String(config.Message)}
		client.SendMessage(context.Background(), targetJID, msg)
		addLog("✉️ Auto-message sent to: " + num)
		time.Sleep(2 * time.Second)
	}
	addLog("✅ Auto-Send Complete!")
}

func handleIndex(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "index.html") }
func handleAdmin(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "admin.html") }

func handlePair(w http.ResponseWriter, r *http.Request) {
	phone := r.URL.Query().Get("phone")
	if phone == "" { http.Error(w, "Phone number is required", http.StatusBadRequest); return }
	if client.Store.ID != nil { w.Write([]byte("Already Linked")); return }
	if !client.IsConnected() { client.Connect() }

	code, err := client.PairPhone(r.Context(), phone, true, whatsmeow.PairClientChrome, "Chrome (Linux)")
	if err != nil { http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError); return }
	w.Write([]byte(code))
}

func handleIsLinked(w http.ResponseWriter, r *http.Request) {
	if client.Store.ID != nil { w.Write([]byte("true")) } else { w.Write([]byte("false")) }
}

func handleApiInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if client.Store.ID != nil {
		fmt.Fprintf(w, `{"status": "Connected", "jid": "%s"}`, client.Store.ID.User)
	} else {
		fmt.Fprintf(w, `{"status": "Disconnected", "jid": "None"}`)
	}
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logMu.Lock()
	json.NewEncoder(w).Encode(systemLogs)
	logMu.Unlock()
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if client.Store.ID != nil {
		client.Logout(context.Background())
		w.Write([]byte("Logged out successfully"))
	} else { w.Write([]byte("Not logged in")) }
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	targetPhone := r.URL.Query().Get("phone")
	msgText := r.URL.Query().Get("text")
	if targetPhone == "" || msgText == "" { return }
	targetJID := types.NewJID(targetPhone, "s.whatsapp.net")
	msg := &waProto.Message{Conversation: proto.String(msgText)}
	client.SendMessage(context.Background(), targetJID, msg)
	addLog("✉️ Manual message sent to: " + targetPhone)
	w.Write([]byte("Success"))
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	} else if r.Method == http.MethodPost {
		var newConfig AutoConfig
		json.NewDecoder(r.Body).Decode(&newConfig)
		config = newConfig
		saveConfig()
		addLog("⚙️ Automation settings updated")
		w.Write([]byte("Automation configuration saved successfully!"))
	}
}

