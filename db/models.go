package db
import "time"

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash string    `gorm:"not null" json:"-"`
	Role         string    `gorm:"default:'admin'" json:"role"`
}

type Device struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Phone     string    `gorm:"uniqueIndex;not null" json:"phone"`
	Status    string    `gorm:"default:'disconnected'" json:"status"`
}

type Message struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	DeviceID  uint       `gorm:"not null;index" json:"device_id"`
	ToPhone   string     `gorm:"not null" json:"to_phone"`
	Text      string     `gorm:"type:text;not null" json:"text"`
	Status    string     `gorm:"default:'queued';index" json:"status"` 
}
