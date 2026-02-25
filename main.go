package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

var (
	client            *whatsmeow.Client
	systemLogs        []string
	logMu             sync.Mutex
	config            AutoConfig
	pairAttempts      = make(map[string]time.Time)
	pairMu            sync.Mutex
	scheduledMessages []ScheduledMessage
	scheduleMu        sync.Mutex
	messageStats      MessageStats
	statsMu           sync.Mutex
)

// Enhanced configuration structure
type AutoConfig struct {
	Enabled     bool              `json:"enabled"`
	Numbers     string            `json:"numbers"`
	Message     string            `json:"message"`
	ReplyEnable bool              `json:"reply_enable"`
	ReplyText   string            `json:"reply_text"`
	Templates   []MessageTemplate `json:"templates"`
	MaxRetries  int               `json:"max_retries"`
	RetryDelay  int               `json:"retry_delay_seconds"`
	SendDelay   int               `json:"send_delay_seconds"`
}

type MessageTemplate struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type ScheduledMessage struct {
	ID          string    `json:"id"`
	Phone       string    `json:"phone"`
	Message     string    `json:"message"`
	ScheduledAt time.Time `json:"scheduled_at"`
	Status      string    `json:"status"`
}

type MessageStats struct {
	TotalSent     int       `json:"total_sent"`
	TotalFailed   int       `json:"total_failed"`
	TotalReceived int       `json:"total_received"`
	LastActivity  time.Time `json:"last_activity"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Enhanced logging with levels
func addLog(msg string, level ...string) {
	logMu.Lock()
	defer logMu.Unlock()

	logLevel := "INFO"
	if len(level) > 0 {
		logLevel = level[0]
	}

	timestamp := time.Now().Format("15:04:05")
	logEntry := fmt.Sprintf("[%s] [%s] %s", timestamp, logLevel, msg)
	systemLogs = append([]string{logEntry}, systemLogs...)

	if len(systemLogs) > 100 {
		systemLogs = systemLogs[:100]
	}
	fmt.Println(logEntry)
}

// Load configuration with defaults
func loadConfig() {
	data, err := os.ReadFile("config.json")
	if err != nil {
		config = AutoConfig{
			Enabled:     false,
			Numbers:     "",
			Message:     "",
			ReplyEnable: false,
			ReplyText:   "",
			Templates:   []MessageTemplate{},
			MaxRetries:  3,
			RetryDelay:  5,
			SendDelay:   2,
		}
		saveConfig()
		return
	}

	if err := json.Unmarshal(data, &config); err != nil {
		addLog("Error loading config: "+err.Error(), "ERROR")
	}

	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5
	}
	if config.SendDelay == 0 {
		config.SendDelay = 2
	}
}

func saveConfig() {
	data, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile("config.json", data, 0644); err != nil {
		addLog("Error saving config: "+err.Error(), "ERROR")
	}
}

// Enhanced security with environment variables and rate limiting
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		adminUser := os.Getenv("ADMIN_USER")
		adminPass := os.Getenv("ADMIN_PASS")

		if adminUser == "" {
			adminUser = "admin"
		}
		if adminPass == "" {
			adminPass = "admin123"
		}

		if !ok || user != adminUser || pass != adminPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Area"`)
			http.Error(w, "Unauthorized Access", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// Rate limiting for pairing attempts
func rateLimitPairing(phone string) bool {
	pairMu.Lock()
	defer pairMu.Unlock()

	if lastAttempt, exists := pairAttempts[phone]; exists {
		if time.Since(lastAttempt) < 30*time.Second {
			return false
		}
	}
	pairAttempts[phone] = time.Now()
	return true
}

// Enhanced event handler with better error handling
func eventHandler(evt interface{}) {
	defer func() {
		if r := recover(); r != nil {
			addLog(fmt.Sprintf("Event handler panic: %v", r), "ERROR")
		}
	}()

	switch v := evt.(type) {
	case *events.Message:
		if !v.Info.IsFromMe {
			sender := "Unknown"
			// Fixed: Check if sender is not empty instead of nil comparison
			if v.Info.Sender.User != "" {
				sender = v.Info.Sender.User
			}

			// Update stats
			statsMu.Lock()
			messageStats.TotalReceived++
			messageStats.LastActivity = time.Now()
			statsMu.Unlock()

			addLog(fmt.Sprintf("📩 Message received from: %s", sender))

			// Enhanced auto-reply with retry mechanism
			if !v.Info.IsGroup && config.ReplyEnable && config.ReplyText != "" {
				go sendAutoReply(v.Info.Sender, config.ReplyText, sender)
			}
		}
	case *events.Connected:
		addLog("🟢 Connected to WhatsApp Server")
	case *events.PairSuccess:
		addLog("✅ Device Successfully Linked!")
		go startAutoSend()
	case *events.LoggedOut:
		addLog("🔴 Device Logged Out")
	case *events.Disconnected:
		addLog("⚠️ Connection lost, attempting to reconnect...", "WARN")
	}
}

// Send auto-reply with retry mechanism
func sendAutoReply(sender types.JID, replyText, senderUser string) {
	defer func() {
		if r := recover(); r != nil {
			addLog(fmt.Sprintf("Auto-reply panic: %v", r), "ERROR")
		}
	}()

	maxRetries := config.MaxRetries
	retryDelay := time.Duration(config.RetryDelay) * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		msg := &waProto.Message{Conversation: proto.String(replyText)}

		if _, err := client.SendMessage(ctx, sender, msg); err != nil {
			cancel()
			addLog(fmt.Sprintf("❌ Auto-reply attempt %d failed to %s: %v", attempt, senderUser, err), "WARN")
			if attempt < maxRetries {
				time.Sleep(retryDelay)
				continue
			}

			statsMu.Lock()
			messageStats.TotalFailed++
			statsMu.Unlock()
		} else {
			cancel()
			addLog("🤖 Auto-reply sent to: " + senderUser)

			statsMu.Lock()
			messageStats.TotalSent++
			messageStats.LastActivity = time.Now()
			statsMu.Unlock()
			break
		}
	}
}

// Enhanced auto-send with better error handling and progress tracking
func startAutoSend() {
	if !config.Enabled || config.Message == "" || config.Numbers == "" {
		return
	}

	addLog("⏳ Starting Auto-Send process...")
	time.Sleep(5 * time.Second)

	rawNumbers := strings.FieldsFunc(config.Numbers, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == ';'
	})

	successCount := 0
	failCount := 0
	totalNumbers := 0

	for _, num := range rawNumbers {
		num = strings.TrimSpace(num)
		if num == "" {
			continue
		}

		num = strings.ReplaceAll(num, "+", "")
		num = strings.ReplaceAll(num, "-", "")
		num = strings.ReplaceAll(num, " ", "")

		if len(num) == 10 && !strings.HasPrefix(num, "91") {
			num = "91" + num
		}

		totalNumbers++
		addLog(fmt.Sprintf("📤 Sending to %s (%d/%d)", num, totalNumbers, len(rawNumbers)))

		if success := sendMessageWithRetry(num, config.Message); success {
			successCount++
		} else {
			failCount++
		}

		time.Sleep(time.Duration(config.SendDelay) * time.Second)
	}

	addLog(fmt.Sprintf("✅ Auto-Send Complete! Total: %d, Success: %d, Failed: %d",
		totalNumbers, successCount, failCount))
}

// Send message with retry mechanism
func sendMessageWithRetry(phone, message string) bool {
	targetJID := types.NewJID(phone, "s.whatsapp.net")
	msg := &waProto.Message{Conversation: proto.String(message)}
	maxRetries := config.MaxRetries
	retryDelay := time.Duration(config.RetryDelay) * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)

		if _, err := client.SendMessage(ctx, targetJID, msg); err != nil {
			cancel()
			addLog(fmt.Sprintf("❌ Send attempt %d to %s failed: %v", attempt, phone, err), "WARN")

			if attempt < maxRetries {
				time.Sleep(retryDelay)
				continue
			}

			statsMu.Lock()
			messageStats.TotalFailed++
			statsMu.Unlock()
			return false
		} else {
			cancel()
			addLog("✉️ Message sent successfully to: " + phone)

			statsMu.Lock()
			messageStats.TotalSent++
			messageStats.LastActivity = time.Now()
			statsMu.Unlock()
			return true
		}
	}
	return false
}

// Generate unique ID
func generateID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func main() {
	loadConfig()
	addLog("🚀 Enhanced WhatsApp Automation Server Started!")

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

	go messageScheduler()

	// Public routes
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/pair", handlePair)
	http.HandleFunc("/is-linked", handleIsLinked)

	// Secure admin routes
	http.HandleFunc("/admin", basicAuth(handleAdmin))
	http.HandleFunc("/api/info", basicAuth(handleApiInfo))
	http.HandleFunc("/api/config", basicAuth(handleConfig))
	http.HandleFunc("/api/logs", basicAuth(handleLogs))
	http.HandleFunc("/api/stats", basicAuth(handleStats))
	http.HandleFunc("/api/templates", basicAuth(handleTemplates))
	http.HandleFunc("/api/schedule", basicAuth(handleScheduleMessage))
	http.HandleFunc("/api/scheduled", basicAuth(handleGetScheduled))
	http.HandleFunc("/api/backup", basicAuth(handleBackup))
	http.HandleFunc("/logout", basicAuth(handleLogout))
	http.HandleFunc("/send", basicAuth(handleSend))
	http.HandleFunc("/bulk-send", basicAuth(handleBulkSend))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addLog(fmt.Sprintf("🌐 Server running on port %s", port))
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// Enhanced handlers
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

	if !rateLimitPairing(phone) {
		http.Error(w, "Too many pairing attempts. Please wait 30 seconds.", http.StatusTooManyRequests)
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
		addLog("Pairing error: "+err.Error(), "ERROR")
		http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	addLog("📱 Pairing code generated for: " + phone)
	w.Write([]byte(code))
}

func handleIsLinked(w http.ResponseWriter, r *http.Request) {
	if client.Store.ID != nil {
		w.Write([]byte("true"))
	} else {
		w.Write([]byte("false"))
	}
}

func handleApiInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if client.Store.ID != nil {
		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"status":    "Connected",
				"jid":       client.Store.ID.User,
				"connected": client.IsConnected(),
			},
		})
	} else {
		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"status":    "Disconnected",
				"jid":       "None",
				"connected": false,
			},
		})
	}
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logMu.Lock()
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Data:    systemLogs,
	})
	logMu.Unlock()
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	statsMu.Lock()
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Data:    messageStats,
	})
	statsMu.Unlock()
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if client.Store.ID != nil {
		client.Logout(context.Background())
		addLog("🔴 Device logged out by admin")
		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Message: "Logged out successfully",
		})
	} else {
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "Not logged in",
		})
	}
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	targetPhone := r.URL.Query().Get("phone")
	msgText := r.URL.Query().Get("text")

	if targetPhone == "" || msgText == "" {
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "Phone and text parameters required",
		})
		return
	}

	targetPhone = strings.ReplaceAll(targetPhone, "+", "")
	targetPhone = strings.ReplaceAll(targetPhone, " ", "")
	targetPhone = strings.ReplaceAll(targetPhone, "-", "")

	if len(targetPhone) == 10 && !strings.HasPrefix(targetPhone, "91") {
		targetPhone = "91" + targetPhone
	}

	success := sendMessageWithRetry(targetPhone, msgText)

	json.NewEncoder(w).Encode(APIResponse{
		Success: success,
		Message: fmt.Sprintf("Message %s", map[bool]string{true: "sent successfully", false: "failed to send"}[success]),
	})
}

func handleBulkSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Numbers []string `json:"numbers"`
		Message string   `json:"message"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "Invalid JSON format",
		})
		return
	}

	go func() {
		successCount := 0
		failCount := 0

		for _, phone := range req.Numbers {
			phone = strings.TrimSpace(phone)
			if phone == "" {
				continue
			}

			if sendMessageWithRetry(phone, req.Message) {
				successCount++
			} else {
				failCount++
			}

			time.Sleep(time.Duration(config.SendDelay) * time.Second)
		}

		addLog(fmt.Sprintf("📊 Bulk send completed: %d success, %d failed", successCount, failCount))
	}()

	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "Bulk sending started in background",
	})
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Data:    config,
		})
	} else if r.Method == http.MethodPost {
		var newConfig AutoConfig
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Message: "Invalid configuration format",
			})
			return
		}

		config = newConfig
		saveConfig()
		addLog("⚙️ Configuration updated by admin")

		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Message: "Configuration saved successfully",
		})
	}
}

func handleTemplates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Data:    config.Templates,
		})
	} else if r.Method == http.MethodPost {
		var template MessageTemplate
		if err := json.NewDecoder(r.Body).Decode(&template); err != nil {
			json.NewEncoder(w).Encode(APIResponse{
				Success: false,
				Message: "Invalid template format",
			})
			return
		}

		config.Templates = append(config.Templates, template)
		saveConfig()
		addLog("📝 New message template added: " + template.Name)

		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Message: "Template added successfully",
		})
	}
}

func handleScheduleMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var msg ScheduledMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "Invalid message format",
		})
		return
	}

	msg.ID = generateID()
	msg.Status = "pending"

	scheduleMu.Lock()
	scheduledMessages = append(scheduledMessages, msg)
	scheduleMu.Unlock()

	addLog(fmt.Sprintf("⏰ Message scheduled for %s to %s", msg.ScheduledAt.Format("2006-01-02 15:04"), msg.Phone))

	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "Message scheduled successfully",
		Data:    msg,
	})
}

func handleGetScheduled(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scheduleMu.Lock()
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Data:    scheduledMessages,
	})
	scheduleMu.Unlock()
}

func handleBackup(w http.ResponseWriter, r *http.Request) {
	data, _ := json.MarshalIndent(map[string]interface{}{
		"config":             config,
		"scheduled_messages": scheduledMessages,
		"stats":              messageStats,
		"backup_date":        time.Now(),
	}, "", "  ")

	w.Header().Set("Content-Disposition", "attachment; filename=whatsapp-backup.json")
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)

	addLog("💾 Configuration backup downloaded by admin")
}

// Message scheduler
func messageScheduler() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		scheduleMu.Lock()
		now := time.Now()

		for i := len(scheduledMessages) - 1; i >= 0; i-- {
			msg := scheduledMessages[i]

			if msg.Status == "pending" && now.After(msg.ScheduledAt) {
				if sendMessageWithRetry(msg.Phone, msg.Message) {
					scheduledMessages[i].Status = "sent"
					addLog(fmt.Sprintf("⏰ Scheduled message sent to %s", msg.Phone))
				} else {
					scheduledMessages[i].Status = "failed"
					addLog(fmt.Sprintf("❌ Scheduled message failed to %s", msg.Phone), "ERROR")
				}
			}

			if now.Sub(msg.ScheduledAt) > 24*time.Hour {
				scheduledMessages = append(scheduledMessages[:i], scheduledMessages[i+1:]...)
			}
		}
		scheduleMu.Unlock()
	}
}
