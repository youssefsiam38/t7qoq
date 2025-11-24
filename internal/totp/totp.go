package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	// DefaultDigits is the default number of digits in the TOTP code
	DefaultDigits = 6
	// DefaultPeriod is the default time period (in seconds) for TOTP
	DefaultPeriod = 30
	// SecretLength is the length of the secret in bytes
	SecretLength = 20
	// BackupCodeCount is the number of backup codes to generate
	BackupCodeCount = 10
)

// GenerateSecret generates a new random secret key
func GenerateSecret() (string, error) {
	bytes := make([]byte, SecretLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes)), nil
}

// GenerateCode generates a TOTP code for the given secret
func GenerateCode(secret string, timestamp time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("invalid secret: %w", err)
	}

	counter := uint64(timestamp.Unix()) / DefaultPeriod
	return generateHOTP(key, counter, DefaultDigits), nil
}

// ValidateCode validates a TOTP code against the secret
// It allows for a window of +/- 1 period to account for time drift
func ValidateCode(secret, code string) bool {
	now := time.Now()

	// Check current time and one period before/after
	for offset := -1; offset <= 1; offset++ {
		checkTime := now.Add(time.Duration(offset*DefaultPeriod) * time.Second)
		expectedCode, err := GenerateCode(secret, checkTime)
		if err != nil {
			continue
		}
		if hmac.Equal([]byte(expectedCode), []byte(code)) {
			return true
		}
	}

	return false
}

// GenerateProvisioningURI generates a URI for adding to authenticator apps
func GenerateProvisioningURI(secret, issuer, accountName string) string {
	secret = strings.ToUpper(secret)
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		issuer, accountName, secret, issuer, DefaultDigits, DefaultPeriod)
}

// GenerateBackupCodes generates a set of one-time backup codes
func GenerateBackupCodes() ([]string, error) {
	codes := make([]string, BackupCodeCount)
	for i := 0; i < BackupCodeCount; i++ {
		bytes := make([]byte, 4)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}
		// Generate 8-digit code
		code := binary.BigEndian.Uint32(bytes) % 100000000
		codes[i] = fmt.Sprintf("%08d", code)
	}
	return codes, nil
}

// ValidateBackupCode checks if a code matches any of the backup codes
// Returns the index of the matching code, or -1 if not found
func ValidateBackupCode(code string, backupCodes []string) int {
	for i, bc := range backupCodes {
		if bc != "" && hmac.Equal([]byte(bc), []byte(code)) {
			return i
		}
	}
	return -1
}

// generateHOTP generates an HOTP code
func generateHOTP(key []byte, counter uint64, digits int) string {
	// Convert counter to big-endian bytes
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	// Calculate HMAC-SHA1
	h := hmac.New(sha1.New, key)
	h.Write(counterBytes)
	hash := h.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0f
	binCode := (uint32(hash[offset])&0x7f)<<24 |
		(uint32(hash[offset+1])&0xff)<<16 |
		(uint32(hash[offset+2])&0xff)<<8 |
		(uint32(hash[offset+3]) & 0xff)

	// Get the digits
	modulo := uint32(1)
	for i := 0; i < digits; i++ {
		modulo *= 10
	}

	code := binCode % modulo
	return fmt.Sprintf("%0*d", digits, code)
}
