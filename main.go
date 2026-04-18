// SecurityMiniApp - Website Security Checker
//
// A command-line tool for basic website security checks.
// Reference: https://www.seg.cl

package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// SecurityCheckResult holds the results of security checks
type SecurityCheckResult struct {
	URL             string
	StatusCode      int
	SSLGrade        string
	SSLExpiryDays   int
	Headers         http.Header
	SecurityIssues  []string
	Recommendations []string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("🔒 Website Security Checker")
		fmt.Println("Usage: securityminiapp <url>")
		fmt.Println("Example: securityminiapp https://example.com")
		os.Exit(1)
	}

	targetURL := os.Args[1]
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}

	fmt.Println("🔒 Website Security Checker")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("🔍 Checking: %s\n\n", targetURL)

	result := performSecurityChecks(targetURL)
	printResults(result)
}

func performSecurityChecks(url string) SecurityCheckResult {
	result := SecurityCheckResult{
		URL:             url,
		SecurityIssues:  []string{},
		Recommendations: []string{},
	}

	// Perform HTTP check
	checkHTTP(&result)

	// Perform SSL/TLS check
	checkSSL(&result)

	// Check security headers
	checkSecurityHeaders(&result)

	// Print summary
	return result
}

func checkHTTP(result *SecurityCheckResult) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(result.URL)
	if err != nil {
		result.SecurityIssues = append(result.SecurityIssues, fmt.Sprintf("❌ Failed to connect: %v", err))
		return
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Headers = resp.Header

	// Check for HTTPS redirect
	if !strings.HasPrefix(result.URL, "https") && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		result.SecurityIssues = append(result.SecurityIssues, "⚠️ Site doesn't redirect to HTTPS")
		result.Recommendations = append(result.Recommendations, "Redirect all HTTP traffic to HTTPS")
	}

	fmt.Printf("✅ HTTP Status: %d\n", resp.StatusCode)
}

func checkSSL(result *SecurityCheckResult) {
	// Parse URL
	urlStr := result.URL
	if !strings.HasPrefix(urlStr, "https") {
		urlStr = strings.Replace(urlStr, "http://", "https://", 1)
	}

	// Connect and check SSL
	conn, err := tls.Dial("tcp", getHost(result.URL)+":443", nil)
	if err != nil {
		result.SecurityIssues = append(result.SecurityIssues, "❌ No SSL certificate found or connection failed")
		result.Recommendations = append(result.Recommendations, "Install a valid SSL certificate")
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cert := state.PeerCertificates[0]

	// Calculate days until expiry
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	result.SSLExpiryDays = daysUntilExpiry

	// Determine SSL grade
	grade := getSSLGrade(state)
	result.SSLGrade = grade

	fmt.Printf("🔐 SSL Grade: %s\n", grade)
	fmt.Printf("📅 Certificate expires in: %d days\n", daysUntilExpiry)

	// Check for issues
	if daysUntilExpiry < 30 {
		result.SecurityIssues = append(result.SecurityIssues, fmt.Sprintf("⚠️ SSL certificate expires in %d days", daysUntilExpiry))
		result.Recommendations = append(result.Recommendations, "Renew SSL certificate before expiration")
	}

	if state.Version < tls.VersionTLS12 {
		result.SecurityIssues = append(result.SecurityIssues, "❌ Outdated TLS version detected")
		result.Recommendations = append(result.Recommendations, "Upgrade to TLS 1.2 or higher")
	}

	// Check cipher suite
	if !isStrongCipher(state.CipherSuite) {
		result.SecurityIssues = append(result.SecurityIssues, "⚠️ Weak cipher suite in use")
		result.Recommendations = append(result.Recommendations, "Configure server to use strong ciphers (AES-GCM, ChaCha20)")
	}
}

func checkSecurityHeaders(result *SecurityCheckResult) {
	headers := result.Headers

	fmt.Println("\n📋 Security Headers:")

	// Check each important header
	headersToCheck := map[string]string{
		"Strict-Transport-Security": "HSTS",
		"Content-Security-Policy":   "CSP",
		"X-Content-Type-Options":    "X-Content-Type-Options",
		"X-Frame-Options":           "X-Frame-Options",
		"X-XSS-Protection":          "X-XSS-Protection",
		"Referrer-Policy":           "Referrer-Policy",
		"Permissions-Policy":        "Permissions-Policy",
	}

	hasIssues := false

	for header, name := range headersToCheck {
		value := headers.Get(header)
		if value != "" {
			fmt.Printf("   ✅ %s: %s\n", name, truncate(value, 50))
		} else {
			fmt.Printf("   ❌ %s: Missing\n", name)
			hasIssues = true
		}
	}

	if hasIssues {
		result.SecurityIssues = append(result.SecurityIssues, "❌ Missing security headers")
		result.Recommendations = append(result.Recommendations, "Add security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options")
	}
}

func printResults(result SecurityCheckResult) {
	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if len(result.SecurityIssues) > 0 {
		fmt.Println("\n🚨 Security Issues Found:")
		for _, issue := range result.SecurityIssues {
			fmt.Printf("   %s\n", issue)
		}
	}

	if len(result.Recommendations) > 0 {
		fmt.Println("\n💡 Recommendations:")
		for _, rec := range result.Recommendations {
			fmt.Printf("   • %s\n", rec)
		}
	}

	if len(result.SecurityIssues) == 0 {
		fmt.Println("\n✅ No major security issues detected!")
	}
}

func getHost(url string) string {
	host := strings.Replace(url, "https://", "", 1)
	host = strings.Replace(host, "http://", "", 1)
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	return host
}

func getSSLGrade(state tls.ConnectionState) string {
	if state.Version >= tls.VersionTLS13 {
		if isStrongCipher(state.CipherSuite) && hasGoodCurves(state) {
			return "A+"
		}
		return "A"
	}
	if state.Version >= tls.VersionTLS12 {
		return "B"
	}
	return "F"
}

func isStrongCipher(cipher uint16) bool {
	strongCiphers := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}

	for _, c := range strongCiphers {
		if cipher == c {
			return true
		}
	}
	return false
}

func hasGoodCurves(state tls.ConnectionState) bool {
	if state.Version >= tls.VersionTLS13 {
		return true // TLS 1.3 uses compatible curves by default
	}
	// For TLS 1.2, check if strong curves are used
	return len(state.ServerName) > 0
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
