package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// PasswordConfig holds password policy configuration
type PasswordConfig struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
	BCryptCost     int
}

// DefaultPasswordConfig returns sensible defaults
func DefaultPasswordConfig() PasswordConfig {
	return PasswordConfig{
		MinLength:      8,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: false,
		BCryptCost:     12,
	}
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string, cost int) (string, error) {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CheckPassword compares a password with a hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ValidatePassword validates a password against the policy
func ValidatePassword(password string, config PasswordConfig) error {
	if len(password) < config.MinLength {
		return errors.New("password must be at least " + string(rune(config.MinLength+'0')) + " characters")
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if config.RequireUpper && !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if config.RequireLower && !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if config.RequireNumber && !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if config.RequireSpecial && !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// GenerateToken generates a secure token for email verification, password reset, etc.
func GenerateToken() (string, error) {
	return GenerateRandomString(32)
}

// GenerateBackupCodes generates 2FA backup codes
func GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := GenerateRandomString(8)
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}
