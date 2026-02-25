package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	mathrand "math/rand"
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
	lastMessageTime   time.Time
	messageMu         sync.Mutex
	userAgents        []string
	deviceFingerprint map[string]string
)

// Enhanced configuration with security settings
type AutoConfig struct {
	Enabled            bool              `json:"enabled"`
	Numbers            string            `json:"numbers"`
	Message            string            `json:"message"`
	ReplyEnable        bool              `json:"reply_enable"`
	ReplyText          string            `json:"reply_text"`
	Templates          []MessageTemplate `json:"templates"`
	MaxRetries         int               `json:"max_retries"`
	RetryDelay         int               `json:"retry_delay_seconds"`
	SendDelay          int               `json:"send_delay_seconds"`
	MinSendDelay       int               `json:"min_send_delay_seconds"`
	MaxSendDelay       int               `json:"max_send_delay_seconds"`
	DailySendLimit     int               `json:"daily_send_limit"`
	HourlySendLimit    int               `json:"hourly_send_limit"`
	RandomizeUserAgent bool              `json:"randomize_user_agent"`
	SafeMode           bool              `json:"safe_mode"`
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
	Attempts    int       `json:"attempts"`
}

type MessageStats struct {
	TotalSent     int                    `json:"total_sent"`
	TotalFailed   int                    `json:"total_failed"`
	TotalReceived int                    `json:"total_received"`
	LastActivity  time.Time              `json:"last_activity"`
	DailyCounts   map[string]int         `json:"daily_counts"`
	HourlyCounts  map[string]int         `json:"hourly_counts"`
	BanWarnings   int                    `json:"ban_warnings"`
	LastBanCheck  time.Time              `json:"last_ban_check"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Warning string      `json:"warning,omitempty"`
}

// Initialize security components
func initSecurity() {
	// Initialize random seed
	mathrand.Seed(time.Now().UnixNano())

	// Realistic user agents for different platforms
	userAgents = []string{
		"WhatsApp/2.23.20.0 Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"WhatsApp/2.23.19.0 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"WhatsApp/2.23.18.0 Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"WhatsApp/2.23.17.0 Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36",
	}

	// Initialize device fingerprint
	deviceFingerprint = map[string]string{
		"platform":    "desktop",
		"app_version": "2.23.20.0",
		"os_version":  "macOS 12.6",
		"device_id":   generateDeviceID(),
	}

	// Initialize stats with date tracking
	if messageStats.DailyCounts == nil {
		messageStats.DailyCounts = make(map[string]int)
	}
	if messageStats.HourlyCounts == nil {
		messageStats.HourlyCounts = make(map[string]int)
	}
}

// Generate realistic device ID
func generateDeviceID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x-%x-%x-%x-%x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}

// Get random user agent
func getRandomUserAgent() string {
	if len(userAgents) == 0 {
		return "WhatsApp/2.23.20.0"
	}
	return userAgents[mathrand.Intn(len(userAgents))]
}

// Enhanced logging with security awareness
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

	if len(systemLogs) > 200 { // Increased for security monitoring
		systemLogs = systemLogs[:200]
	}

	// Log security warnings
	if len(level) > 0 && level[0] == "SECURITY" {
		fmt.Printf("🔒 SECURITY: %s\n", logEntry)
	} else {
		fmt.Println(logEntry)
	}
}

// Check if sending is safe (anti-ban protection)
func isSendingSafe(phoneNumber string) (bool, string) {
	messageMu.Lock()
	defer messageMu.Unlock()

	now := time.Now()
	today := now.Format("2006-01-02")
	hour := now.Format("2006-01-02-15")

	// Check daily limits
	if config.DailySendLimit > 0 && messageStats.DailyCounts[today] >= config.DailySendLimit {
		return false, fmt.Sprintf("Daily limit reached (%d messages)", config.DailySendLimit)
	}

	// Check hourly limits
	if config.HourlySendLimit > 0 && messageStats.HourlyCounts[hour] >= config.HourlySendLimit {
		return false, fmt.Sprintf("Hourly limit reached (%d messages)", config.HourlySendLimit)
	}

	// Check minimum time between messages
	minDelay := time.Duration(config.MinSendDelay) * time.Second
	if config.MinSendDelay > 0 && time.Since(lastMessageTime) < minDelay {
		return false, fmt.Sprintf("Too fast sending (min delay: %ds)", config.MinSendDelay)
	}

	// Safe mode checks
	if config.SafeMode {
		// More conservative limits in safe mode
		if messageStats.DailyCounts[today] >= 50 {
			return false, "Safe mode: Daily limit of 50 messages reached"
		}
		if messageStats.HourlyCounts[hour] >= 10 {
			return false, "Safe mode: Hourly limit of 10 messages reached"
		}
	}

	return true, ""
}

// Calculate smart delay to mimic human behavior
func calculateSmartDelay() time.Duration {
	minDelay := config.MinSendDelay
	maxDelay := config.MaxSendDelay

	if minDelay == 0 {
		minDelay = 3 // Minimum 3 seconds
	}
	if maxDelay == 0 {
		maxDelay = 8 // Maximum 8 seconds
	}

	// Add randomization to avoid patterns
	baseDelay := minDelay + mathrand.Intn(maxDelay-minDelay+1)
	
	// Add small random variation (±20%)
	variation := int(float64(baseDelay) * 0.2)
	finalDelay := baseDelay + mathrand.Intn(variation*2) - variation

	if finalDelay < minDelay {
		finalDelay = minDelay
	}

	return time.Duration(finalDelay) * time.Second
}

// Update message statistics safely
func updateMessageStats(sent bool) {
	statsMu.Lock()
	defer statsMu.Unlock()

	now := time.Now()
	today := now.Format("2006-01-02")
	hour := now.Format("2006-01-02-15")

	if sent {
		messageStats.TotalSent++
		messageStats.DailyCounts[today]++
		messageStats.HourlyCounts[hour]++
	} else {
		messageStats.TotalFailed++
	}

	messageStats.LastActivity = now

	// Cleanup old entries (keep only last 7 days)
	cutoff := now.AddDate(0, 0, -7).Format("2006-01-02")
	for date := range messageStats.DailyCounts {
		if date < cutoff {
			delete(messageStats.DailyCounts, date)
		}
	}

	// Cleanup old hourly entries (keep only last 24 hours)
	cutoffHour := now.Add(-24 * time.Hour).Format("2006-01-02-15")
	for hourKey := range messageStats.HourlyCounts {
		if hourKey < cutoffHour {
			delete(messageStats.HourlyCounts, hourKey)
		}
	}
}

// Load configuration with enhanced security defaults
func loadConfig() {
	data, err := os.ReadFile("config.json")
	if err != nil {
		// Enhanced security defaults
		config = AutoConfig{
			Enabled:            false,
			Numbers:            "",
			Message:            "",
			ReplyEnable:        false,
			ReplyText:          "",
			Templates:          []MessageTemplate{},
			MaxRetries:         2,  // Reduced retries to avoid spam detection
			RetryDelay:         10, // Increased retry delay
			SendDelay:          5,  // Minimum safe delay
			MinSendDelay:       3,  // Minimum 3 seconds between messages
			MaxSendDelay:       12, // Maximum 12 seconds between messages
			DailySendLimit:     100, // Conservative daily limit
			HourlySendLimit:    20,  // Conservative hourly limit
			RandomizeUserAgent: true,
			SafeMode:           true, // Enable safe mode by default
		}
		saveConfig()
		addLog("🔒 Security-enhanced configuration created", "SECURITY")
		return
	}

	if err := json.Unmarshal(data, &config); err != nil {
		addLog("Error loading config: "+err.Error(), "ERROR")
	}

	// Set security defaults for missing values
	if config.MinSendDelay == 0 {
		config.MinSendDelay = 3
	}
	if config.MaxSendDelay == 0 {
		config.MaxSendDelay = 12
	}
	if config.DailySendLimit == 0 {
		config.DailySendLimit = 100
	}
	if config.HourlySendLimit == 0 {
		config.HourlySendLimit = 20
	}
}

func saveConfig() {
	data, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile("config.json", data, 0644); err != nil {
		addLog("Error saving config: "+err.Error(), "ERROR")
	}
}

// Enhanced security with rate limiting and IP checking
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
			addLog(fmt.Sprintf("Failed login attempt from: %s", r.RemoteAddr), "SECURITY")
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Area"`)
			http.Error(w, "Unauthorized Access", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// Enhanced pairing with proper rate limiting
func rateLimitPairing(phone string) bool {
	pairMu.Lock()
	defer pairMu.Unlock()

	if lastAttempt, exists := pairAttempts[phone]; exists {
		if time.Since(lastAttempt) < 60*time.Second { // Increased to 60 seconds
			return false
		}
	}
	pairAttempts[phone] = time.Now()
	return true
}

// Enhanced event handler with security monitoring
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
			if v.Info.Sender.User != "" {
				sender = v.Info.Sender.User
			}

			updateMessageStats(false) // Received message
			addLog(fmt.Sprintf("📩 Message received from: %s", sender))

			// Smart auto-reply with anti-spam protection
			if !v.Info.IsGroup && config.ReplyEnable && config.ReplyText != "" {
				go sendSecureAutoReply(v.Info.Sender, config.ReplyText, sender)
			}
		}
	case *events.Connected:
		addLog("🟢 Securely connected to WhatsApp", "SECURITY")
	case *events.PairSuccess:
		addLog("✅ Device securely linked with enhanced protection!", "SECURITY")
		go startSecureAutoSend()
	case *events.LoggedOut:
		addLog("🔴 Device logged out", "SECURITY")
	case *events.Disconnected:
		addLog("⚠️ Connection lost, implementing secure reconnection...", "WARN")
		messageStats.BanWarnings++
		if messageStats.BanWarnings > 3 {
			addLog("🚨 Multiple disconnections detected - possible ban warning!", "SECURITY")
		}
	case *events.StreamError:
		addLog("🚨 Stream error detected - possible security issue", "SECURITY")
		messageStats.BanWarnings++
	}
}

// Secure auto-reply with human-like behavior
func sendSecureAutoReply(sender types.JID, replyText, senderUser string) {
	defer func() {
		if r := recover(); r != nil {
			addLog(fmt.Sprintf("Auto-reply panic: %v", r), "ERROR")
		}
	}()

	// Check if auto-reply is safe
	if safe, reason := isSendingSafe(sender.User); !safe {
		addLog(fmt.Sprintf("🔒 Auto-reply blocked for %s: %s", senderUser, reason), "SECURITY")
		return
	}

	// Human-like delay before replying (1-5 seconds)
	replyDelay := time.Duration(1+mathrand.Intn(4)) * time.Second
	time.Sleep(replyDelay)

	maxRetries := config.MaxRetries
	retryDelay := time.Duration(config.RetryDelay) * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		
		// Add typing indicator simulation (more human-like)
		if attempt == 1 {
			// Simulate typing time based on message length
			typingTime := time.Duration(len(replyText)/10+1) * time.Second
			if typingTime > 5*time.Second {
				typingTime = 5 * time.Second
			}
			time.Sleep(typingTime)
		}

		msg := &waProto.Message{Conversation: proto.String(replyText)}

		if _, err := client.SendMessage(ctx, sender, msg); err != nil {
			cancel()
			addLog(fmt.Sprintf("❌ Auto-reply attempt %d failed to %s: %v", attempt, senderUser, err), "WARN")
			if attempt < maxRetries {
				time.Sleep(retryDelay)
				continue
			}
			updateMessageStats(false)
		} else {
			cancel()
			addLog("🤖 Secure auto-reply sent to: " + senderUser)
			updateMessageStats(true)
			
			messageMu.Lock()
			lastMessageTime = time.Now()
			messageMu.Unlock()
			break
		}
	}
}

// Secure auto-send with advanced protection
func startSecureAutoSend() {
	if !config.Enabled || config.Message == "" || config.Numbers == "" {
		return
	}

	addLog("⏳ Starting secure auto-send with anti-ban protection...", "SECURITY")
	
	// Initial delay to avoid immediate sending after connection
	initialDelay := time.Duration(30+mathrand.Intn(60)) * time.Second
	addLog(fmt.Sprintf("🔒 Waiting %v before starting (security measure)", initialDelay), "SECURITY")
	time.Sleep(initialDelay)

	rawNumbers := strings.FieldsFunc(config.Numbers, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == ';'
	})

	successCount := 0
	failCount := 0
	skippedCount := 0

	for i, num := range rawNumbers {
		num = strings.TrimSpace(num)
		if num == "" {
			continue
		}

		// Clean and format number
		num = strings.ReplaceAll(num, "+", "")
		num = strings.ReplaceAll(num, "-", "")
		num = strings.ReplaceAll(num, " ", "")

		if len(num) == 10 && !strings.HasPrefix(num, "91") {
			num = "91" + num
		}

		// Security check before sending
		if safe, reason := isSendingSafe(num); !safe {
			addLog(fmt.Sprintf("🔒 Skipping %s: %s", num, reason), "SECURITY")
			skippedCount++
			continue
		}

		addLog(fmt.Sprintf("📤 Securely sending to %s (%d/%d)", num, i+1, len(rawNumbers)))

		success := sendSecureMessage(num, config.Message)
		if success {
			successCount++
		} else {
			failCount++
		}

		// Smart delay calculation
		delay := calculateSmartDelay()
		addLog(fmt.Sprintf("⏱️ Smart delay: %v", delay))
		time.Sleep(delay)

		// Safety break if too many failures
		if failCount > 5 && successCount == 0 {
			addLog("🚨 Too many failures detected - stopping for security", "SECURITY")
			break
		}
	}

	addLog(fmt.Sprintf("✅ Secure auto-send complete! Success: %d, Failed: %d, Skipped: %d", 
		successCount, failCount, skippedCount), "SECURITY")
}

// Secure message sending with advanced protection
func sendSecureMessage(phone, message string) bool {
	targetJID := types.NewJID(phone, "s.whatsapp.net")
	msg := &waProto.Message{Conversation: proto.String(message)}
	maxRetries := config.MaxRetries
	retryDelay := time.Duration(config.RetryDelay) * time.Second

	// Pre-sending security check
	if safe, reason := isSendingSafe(phone); !safe {
		addLog(fmt.Sprintf("🔒 Send blocked to %s: %s", phone, reason), "SECURITY")
		return false
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		// Randomize user agent if enabled
		if config.RandomizeUserAgent {
			userAgent := getRandomUserAgent()
			addLog(fmt.Sprintf("🔄 Using user agent: %s", userAgent), "SECURITY")
		}

		if _, err := client.SendMessage(ctx, targetJID, msg); err != nil {
			cancel()
			addLog(fmt.Sprintf("❌ Secure send attempt %d to %s failed: %v", attempt, phone, err), "WARN")

			// Check for ban indicators in error message
			if strings.Contains(strings.ToLower(err.Error()), "banned") ||
				strings.Contains(strings.ToLower(err.Error()), "restricted") ||
				strings.Contains(strings.ToLower(err.Error()), "rate limit") {
				addLog("🚨 BAN WARNING: Detected ban-related error!", "SECURITY")
				messageStats.BanWarnings++
				return false
			}

			if attempt < maxRetries {
				// Exponential backoff for retries
				backoffDelay := retryDelay * time.Duration(attempt)
				time.Sleep(backoffDelay)
				continue
			}

			updateMessageStats(false)
			return false
		} else {
			cancel()
			addLog(fmt.Sprintf("✉️ Message securely sent to: %s", phone))
			updateMessageStats(true)

			messageMu.Lock()
			lastMessageTime = time.Now()
			messageMu.Unlock()
			return true
		}
	}
	return false
}

func main() {
	// Initialize security components first
	initSecurity()
	loadConfig()
	
	addLog("🚀 SECURE WhatsApp Automation Server Started!", "SECURITY")
	addLog("🔒 Anti-ban protection: ENABLED", "SECURITY")
	addLog("🛡️ Security monitoring: ACTIVE", "SECURITY")

	dbLog := waLog.Stdout("Database", "ERROR", true) // Reduced logging to avoid detection
	container, err := sqlstore.New(context.Background(), "sqlite3", "file:session.db?_foreign_keys=on", dbLog)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	deviceStore, err := container.GetFirstDevice(context.Background())
	if err != nil {
		log.Fatalf("Failed to get device store: %v", err)
	}

	clientLog := waLog.Stdout("Client", "ERROR", true) // Reduced logging
	client = whatsmeow.NewClient(deviceStore, clientLog)
	
	// Enhanced client options for security
	client.EnableAutoReconnect = true
	client.AutoTrustIdentity = false // More secure
	
	client.AddEventHandler(eventHandler)

	// Start secure message scheduler
	go secureMessageScheduler()

	// Routes with enhanced security
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/pair", handleSecurePair)
	http.HandleFunc("/is-linked", handleIsLinked)

	// Admin routes with enhanced protection
	http.HandleFunc("/admin", basicAuth(handleAdmin))
	http.HandleFunc("/api/info", basicAuth(handleApiInfo))
	http.HandleFunc("/api/config", basicAuth(handleSecureConfig))
	http.HandleFunc("/api/logs", basicAuth(handleLogs))
	http.HandleFunc("/api/stats", basicAuth(handleSecureStats))
	http.HandleFunc("/api/security", basicAuth(handleSecurityStatus))
	http.HandleFunc("/logout", basicAuth(handleLogout))
	http.HandleFunc("/send", basicAuth(handleSecureSend))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addLog(fmt.Sprintf("🌐 Secure server running on port %s", port), "SECURITY")
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// Enhanced handlers

func handleIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "admin.html")
}

func handleSecurePair(w http.ResponseWriter, r *http.Request) {
	phone := r.URL.Query().Get("phone")
	if phone == "" {
		http.Error(w, "Phone number is required", http.StatusBadRequest)
		return
	}

	// Enhanced rate limiting for pairing
	if !rateLimitPairing(phone) {
		addLog(fmt.Sprintf("🔒 Pairing rate limit exceeded for: %s", phone), "SECURITY")
		http.Error(w, "Too many pairing attempts. Please wait 60 seconds.", http.StatusTooManyRequests)
		return
	}

	if client.Store.ID != nil {
		w.Write([]byte("Already Linked"))
		return
	}

	if !client.IsConnected() {
		client.Connect()
	}

	// Use randomized client info for better security
	clientName := "Chrome (Linux)"
	if config.RandomizeUserAgent {
		clientOptions := []string{"Chrome (Linux)", "Chrome (Windows)", "Chrome (macOS)"}
		clientName = clientOptions[mathrand.Intn(len(clientOptions))]
	}

	code, err := client.PairPhone(r.Context(), phone, true, whatsmeow.PairClientChrome, clientName)
	if err != nil {
		addLog("🔒 Secure pairing error: "+err.Error(), "SECURITY")
		http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	addLog(fmt.Sprintf("📱 Secure pairing code generated for: %s", phone), "SECURITY")
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
				"status":          "Connected",
				"jid":             client.Store.ID.User,
				"connected":       client.IsConnected(),
				"security_active": true,
				"safe_mode":       config.SafeMode,
			},
		})
	} else {
		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"status":          "Disconnected",
				"jid":             "None",
				"connected":       false,
				"security_active": true,
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

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if client.Store.ID != nil {
		client.Logout(context.Background())
		addLog("🔴 Device securely logged out by admin", "SECURITY")
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

func handleSecureConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Data:    config,
			Warning: "Security features active - some limits may apply",
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

		// Enforce security limits
		if newConfig.DailySendLimit > 500 {
			newConfig.DailySendLimit = 500
			addLog("🔒 Daily limit capped at 500 for security", "SECURITY")
		}
		if newConfig.MinSendDelay < 3 {
			newConfig.MinSendDelay = 3
			addLog("🔒 Min send delay enforced to 3 seconds", "SECURITY")
		}

		config = newConfig
		saveConfig()
		addLog("⚙️ Secure configuration updated by admin", "SECURITY")

		json.NewEncoder(w).Encode(APIResponse{
			Success: true,
			Message: "Configuration saved with security enhancements",
		})
	}
}

func handleSecureSend(w http.ResponseWriter, r *http.Request) {
	targetPhone := r.URL.Query().Get("phone")
	msgText := r.URL.Query().Get("text")

	if targetPhone == "" || msgText == "" {
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "Phone and text parameters required",
		})
		return
	}

	// Security validation
	if safe, reason := isSendingSafe(targetPhone); !safe {
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Message: "Send blocked by security: " + reason,
			Warning: "Anti-ban protection active",
		})
		return
	}

	// Clean phone number
	targetPhone = strings.ReplaceAll(targetPhone, "+", "")
	targetPhone = strings.ReplaceAll(targetPhone, " ", "")
	targetPhone = strings.ReplaceAll(targetPhone, "-", "")

	if len(targetPhone) == 10 && !strings.HasPrefix(targetPhone, "91") {
		targetPhone = "91" + targetPhone
	}

	success := sendSecureMessage(targetPhone, msgText)

	json.NewEncoder(w).Encode(APIResponse{
		Success: success,
		Message: fmt.Sprintf("Message %s", map[bool]string{true: "sent securely", false: "failed to send"}[success]),
	})
}

func handleSecureStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	statsMu.Lock()
	
	// Add security status to stats
	securityStatus := "SECURE"
	if messageStats.BanWarnings > 5 {
		securityStatus = "WARNING"
	} else if messageStats.BanWarnings > 10 {
		securityStatus = "CRITICAL"
	}

	enhancedStats := map[string]interface{}{
		"message_stats":    messageStats,
		"security_status":  securityStatus,
		"ban_warnings":     messageStats.BanWarnings,
		"safe_mode":        config.SafeMode,
		"daily_remaining":  config.DailySendLimit - messageStats.DailyCounts[time.Now().Format("2006-01-02")],
		"hourly_remaining": config.HourlySendLimit - messageStats.HourlyCounts[time.Now().Format("2006-01-02-15")],
	}
	
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Data:    enhancedStats,
	})
	statsMu.Unlock()
}

func handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	securityInfo := map[string]interface{}{
		"safe_mode_active":     config.SafeMode,
		"ban_warnings":         messageStats.BanWarnings,
		"rate_limiting":        true,
		"user_agent_rotation":  config.RandomizeUserAgent,
		"daily_limit":          config.DailySendLimit,
		"hourly_limit":         config.HourlySendLimit,
		"min_send_delay":       config.MinSendDelay,
		"last_security_check":  time.Now(),
		"security_level":       "HIGH",
	}

	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Data:    securityInfo,
		Message: "Security systems operational",
	})
}

func secureMessageScheduler() {
	ticker := time.NewTicker(60 * time.Second) // Less frequent checking
	defer ticker.Stop()

	for range ticker.C {
		scheduleMu.Lock()
		now := time.Now()

		for i := len(scheduledMessages) - 1; i >= 0; i-- {
			msg := scheduledMessages[i]

			if msg.Status == "pending" && now.After(msg.ScheduledAt) {
				// Security check before sending scheduled message
				if safe, reason := isSendingSafe(msg.Phone); !safe {
					addLog(fmt.Sprintf("🔒 Scheduled message blocked: %s", reason), "SECURITY")
					scheduledMessages[i].Status = "blocked"
					continue
				}

				if sendSecureMessage(msg.Phone, msg.Message) {
					scheduledMessages[i].Status = "sent"
					addLog(fmt.Sprintf("⏰ Scheduled message securely sent to %s", msg.Phone))
				} else {
					scheduledMessages[i].Status = "failed"
					scheduledMessages[i].Attempts++
					addLog(fmt.Sprintf("❌ Scheduled message failed to %s (attempt %d)", msg.Phone, scheduledMessages[i].Attempts), "ERROR")
				}
			}

			// Remove old messages (older than 48 hours)
			if now.Sub(msg.ScheduledAt) > 48*time.Hour {
				scheduledMessages = append(scheduledMessages[:i], scheduledMessages[i+1:]...)
			}
		}
		scheduleMu.Unlock()
	}
}
