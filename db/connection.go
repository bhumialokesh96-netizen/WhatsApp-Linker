package db
import (
	"log"
	"os"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	var err error
	dsn := os.Getenv("DATABASE_URL")

	if dsn != "" {
		DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		log.Println("🌍 Connected to Render PostgreSQL")
	} else {
		DB, err = gorm.Open(sqlite.Open("enterprise.db"), &gorm.Config{})
		log.Println("🏠 Connected to Local SQLite")
	}

	if err != nil { log.Fatal("❌ DB Error:", err) }

	DB.AutoMigrate(&User{}, &Device{}, &Message{})
	log.Println("✅ Database Setup Complete!")
}
