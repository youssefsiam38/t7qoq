package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"

	emailtemplates "github.com/youssefsiam38/t7qoq/internal/email/templates"
)

// Config holds SMTP configuration
type Config struct {
	Host       string
	Port       int
	Username   string
	Password   string
	From       string
	FromName   string
	Encryption string // "tls", "ssl", "none"
}

// Service handles sending emails
type Service struct {
	config    Config
	templates *template.Template
}

// NewService creates a new email service with embedded templates
func NewService(config Config) (*Service, error) {
	tmpl, err := template.ParseFS(emailtemplates.EmailTemplates, "*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse email templates: %w", err)
	}

	return &Service{
		config:    config,
		templates: tmpl,
	}, nil
}

// NewServiceWithoutTemplates creates a new email service without templates (for disabled email)
func NewServiceWithoutTemplates(config Config) *Service {
	return &Service{
		config:    config,
		templates: nil,
	}
}

// SetTemplates sets the email templates
func (s *Service) SetTemplates(templates *template.Template) {
	s.templates = templates
}

// SendEmail sends an email
func (s *Service) SendEmail(to, subject, body string) error {
	if s.config.Host == "" {
		return fmt.Errorf("SMTP host not configured")
	}

	from := s.config.From
	if s.config.FromName != "" {
		from = fmt.Sprintf("%s <%s>", s.config.FromName, s.config.From)
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n%s",
		from, to, subject, body)

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	var auth smtp.Auth
	if s.config.Username != "" && s.config.Password != "" {
		auth = smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	}

	switch strings.ToLower(s.config.Encryption) {
	case "tls", "starttls":
		return s.sendWithTLS(addr, auth, s.config.From, []string{to}, []byte(msg))
	case "ssl":
		return s.sendWithSSL(addr, auth, s.config.From, []string{to}, []byte(msg))
	default:
		return smtp.SendMail(addr, auth, s.config.From, []string{to}, []byte(msg))
	}
}

// sendWithTLS sends email using STARTTLS
func (s *Service) sendWithTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()

	tlsconfig := &tls.Config{
		ServerName: s.config.Host,
	}

	if err = c.StartTLS(tlsconfig); err != nil {
		return err
	}

	if auth != nil {
		if err = c.Auth(auth); err != nil {
			return err
		}
	}

	if err = c.Mail(from); err != nil {
		return err
	}

	for _, recipient := range to {
		if err = c.Rcpt(recipient); err != nil {
			return err
		}
	}

	w, err := c.Data()
	if err != nil {
		return err
	}

	_, err = w.Write(msg)
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	return c.Quit()
}

// sendWithSSL sends email using SSL
func (s *Service) sendWithSSL(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	tlsconfig := &tls.Config{
		ServerName: s.config.Host,
	}

	conn, err := tls.Dial("tcp", addr, tlsconfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		return err
	}
	defer c.Close()

	if auth != nil {
		if err = c.Auth(auth); err != nil {
			return err
		}
	}

	if err = c.Mail(from); err != nil {
		return err
	}

	for _, recipient := range to {
		if err = c.Rcpt(recipient); err != nil {
			return err
		}
	}

	w, err := c.Data()
	if err != nil {
		return err
	}

	_, err = w.Write(msg)
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	return c.Quit()
}

// EmailData holds data for email templates
type EmailData struct {
	Subject     string
	AppName     string
	UserName    string
	UserEmail   string
	ActionURL   string
	SupportURL  string
	CompanyName string
	Year        int
}

// IsConfigured returns true if SMTP is configured
func (s *Service) IsConfigured() bool {
	return s.config.Host != ""
}

// SendTemplatedEmail sends an email using a template
func (s *Service) SendTemplatedEmail(to, templateName, subject string, data EmailData) error {
	if s.templates == nil {
		return fmt.Errorf("email templates not configured")
	}

	// Set subject in data for template access
	data.Subject = subject

	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, templateName, data); err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	return s.SendEmail(to, subject, buf.String())
}

// SendWelcomeEmail sends a welcome email
func (s *Service) SendWelcomeEmail(to, userName, verifyURL string, data EmailData) error {
	data.UserName = userName
	data.ActionURL = verifyURL
	return s.SendTemplatedEmail(to, "welcome.html", fmt.Sprintf("Welcome to %s", data.AppName), data)
}

// SendVerificationEmail sends an email verification email
func (s *Service) SendVerificationEmail(to, userName, verifyURL string, data EmailData) error {
	data.UserName = userName
	data.ActionURL = verifyURL
	return s.SendTemplatedEmail(to, "verify-email.html", "Verify your email address", data)
}

// SendPasswordResetEmail sends a password reset email
func (s *Service) SendPasswordResetEmail(to, userName, resetURL string, data EmailData) error {
	data.UserName = userName
	data.ActionURL = resetURL
	return s.SendTemplatedEmail(to, "reset-password.html", "Reset your password", data)
}

// SendPasswordChangedEmail sends a notification that password was changed
func (s *Service) SendPasswordChangedEmail(to, userName string, data EmailData) error {
	data.UserName = userName
	return s.SendTemplatedEmail(to, "password-changed.html", "Your password was changed", data)
}

// SendOrganizationInviteEmail sends an organization invitation email
func (s *Service) SendOrganizationInviteEmail(to, inviterName, orgName, inviteURL string, data EmailData) error {
	data.UserName = inviterName
	data.ActionURL = inviteURL
	data.CompanyName = orgName
	return s.SendTemplatedEmail(to, "org-invite.html", fmt.Sprintf("You've been invited to join %s", orgName), data)
}
