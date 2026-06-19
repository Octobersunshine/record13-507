package config

import (
	"os"
)

type Config struct {
	ServerPort    string
	JWTSecret     string
	AESKey        string
	DatabasePath  string
	TokenExpire   int
}

var AppConfig *Config

func LoadConfig() {
	AppConfig = &Config{
		ServerPort:   getEnv("SERVER_PORT", ":8080"),
		JWTSecret:    getEnv("JWT_SECRET", "privilege-vault-super-secret-key-2024"),
		AESKey:       getEnv("AES_KEY", "12345678901234567890123456789012"),
		DatabasePath: getEnv("DB_PATH", "privilege_vault.db"),
		TokenExpire:  24,
	}
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
