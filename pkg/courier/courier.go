// Package courier delivers scan results to external platforms: Slack,
// Discord, Telegram, and generic webhook endpoints. One notification
// after a scan replaces the need to watch the terminal.
package courier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Missive holds the message payload and delivery targets.
type Missive struct {
	Target   string
	Date     time.Time
	Stats    Stats
	TopFindings []string
}

// Stats summarizes scan results for notification.
type Stats struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Duration time.Duration
}

// ── Message builders ─────────────────────────────────────────────────────

// Slack builds a Slack-compatible webhook payload.
func (m *Missive) Slack() map[string]interface{} {
	color := "#36a64f" // green
	if m.Stats.Critical > 0 { color = "#ff0000" }
	if m.Stats.Critical == 0 && m.Stats.High > 0 { color = "#ff6600" }

	text := fmt.Sprintf(":mag: *sxsc scan completed* — `%s`", m.Target)
	if m.Stats.Total == 0 {
		text += "\n:white_check_mark: No vulnerabilities found."
	} else {
		text += fmt.Sprintf("\n:rotating_light: %d finding(s): *%d critical*, %d high, %d medium, %d low",
			m.Stats.Total, m.Stats.Critical, m.Stats.High, m.Stats.Medium, m.Stats.Low)
	}

	for _, f := range m.TopFindings {
		text += "\n  - " + f
	}

	text += fmt.Sprintf("\n`Duration: %v`", m.Stats.Duration.Round(time.Second))

	return map[string]interface{}{
		"attachments": []map[string]interface{}{{
			"color":   color,
			"title":   "sxsc Scan Report",
			"text":    text,
			"footer":  "sxsc — SentinelX Scanner",
			"ts":      m.Date.Unix(),
		}},
	}
}

// Discord builds a Discord-compatible webhook payload.
func (m *Missive) Discord() map[string]interface{} {
	color := 3066993 // green
	if m.Stats.Critical > 0 { color = 15158332 }
	if m.Stats.Critical == 0 && m.Stats.High > 0 { color = 16740608 }

	var fields []map[string]interface{}
	if m.Stats.Critical > 0 {
		fields = append(fields, map[string]interface{}{"name": "CRITICAL", "value": fmt.Sprintf("%d", m.Stats.Critical), "inline": true})
	}
	if m.Stats.High > 0 {
		fields = append(fields, map[string]interface{}{"name": "HIGH", "value": fmt.Sprintf("%d", m.Stats.High), "inline": true})
	}
	if m.Stats.Medium > 0 {
		fields = append(fields, map[string]interface{}{"name": "MEDIUM", "value": fmt.Sprintf("%d", m.Stats.Medium), "inline": true})
	}

	title := fmt.Sprintf("Scan Complete — %s", m.Target)
	if m.Stats.Total == 0 {
		title = fmt.Sprintf("Scan Complete (Clean) — %s", m.Target)
	}

	emb := map[string]interface{}{
		"title":       title,
		"color":       color,
		"description": fmt.Sprintf("%d findings in %v", m.Stats.Total, m.Stats.Duration.Round(time.Second)),
		"timestamp":   m.Date.Format(time.RFC3339),
	}
	if len(fields) > 0 {
		emb["fields"] = fields
	}
	if len(m.TopFindings) > 0 {
		emb["description"] = emb["description"].(string) + "\n" + strings.Join(m.TopFindings[:min(5, len(m.TopFindings))], "\n")
	}

	return map[string]interface{}{
		"embeds": []map[string]interface{}{emb},
	}
}

// Telegram builds a Telegram Bot API message.
func (m *Missive) Telegram() string {
	if m.Stats.Total == 0 {
		return fmt.Sprintf("*sxsc Scan Complete*\nTarget: `%s`\nNo vulnerabilities found.\nDuration: %v",
			m.Target, m.Stats.Duration.Round(time.Second))
	}

	msg := fmt.Sprintf("*sxsc Scan Complete*\nTarget: `%s`\n", m.Target)
	msg += fmt.Sprintf("%d finding(s): *%d critical*, %d high, %d medium, %d low\n",
		m.Stats.Total, m.Stats.Critical, m.Stats.High, m.Stats.Medium, m.Stats.Low)
	for _, f := range m.TopFindings[:min(3, len(m.TopFindings))] {
		msg += fmt.Sprintf("- %s\n", f)
	}
	msg += fmt.Sprintf("\nDuration: %v", m.Stats.Duration.Round(time.Second))
	return msg
}

// ── Delivery ─────────────────────────────────────────────────────────────

// Deliver sends the missive to the configured webhook URL. Auto-detects
// platform from the URL (Slack, Discord, or generic).
func (m *Missive) Deliver(webhookURL string) error {
	var payload map[string]interface{}
	contentType := "application/json"

	switch {
	case strings.Contains(webhookURL, "slack.com"):
		payload = m.Slack()
	case strings.Contains(webhookURL, "discord.com"):
		payload = m.Discord()
	case strings.Contains(webhookURL, "telegram"):
		return m.deliverTelegram(webhookURL)
	default:
		payload = m.Slack() // generic fallback
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, contentType, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("  [courier] Notification sent to %s (HTTP %d)\n",
		extractHost(webhookURL), resp.StatusCode)
	return nil
}

func (m *Missive) deliverTelegram(webhookURL string) error {
	payload := map[string]string{
		"chat_id":    extractTelegramChatID(webhookURL),
		"text":       m.Telegram(),
		"parse_mode": "Markdown",
	}
	data, _ := json.Marshal(payload)
	baseURL := webhookURL[:strings.LastIndex(webhookURL, "/")]
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(baseURL+"/sendMessage", "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────

func extractHost(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rest := rawURL[idx+3:]
		if idx := strings.Index(rest, "/"); idx >= 0 {
			return rest[:idx]
		}
		return rest
	}
	return rawURL
}

func extractTelegramChatID(url string) string {
	// Extract chat_id from URL like https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>
	if idx := strings.LastIndex(url, "chat_id="); idx >= 0 {
		return url[idx+8:]
	}
	return ""
}
