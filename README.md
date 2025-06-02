# send-secure-email

A Secure Azure Function for sending emails with multiple layers of security protection. Here are the key security features implemented:

# Security Features

## Authentication & Authorization:

API key validation with timing-attack resistant comparison
Function-level authorization requirement

## Rate Limiting:

10 requests per hour per IP address
Sliding window rate limiting with in-memory cache
Automatic counter reset after time window

## Input Validation:

Data annotations for email format, string length limits
JSON schema validation
Email domain restrictions (configurable)
Suspicious content detection (spam/malicious patterns)

## Content Security:

HTML injection prevention (plain text emails only)
Script tag detection and blocking
Suspicious pattern matching for common spam/phishing attempts
Character limits to prevent abuse

## Infrastructure Security:

Secure credential storage via environment variables
SMTP over SSL/TLS
Connection timeouts to prevent hanging connections
Proper error handling without information leakage

# Required Environment Variables

## Set these in your Azure Function configuration:

```
EMAIL_API_KEY=your-secret-api-key-here
SMTP_HOST=smtp.yourmailserver.com
SMTP_USER=your-smtp-username
SMTP_PASS=your-smtp-password
SMTP_PORT=587
ALLOWED_DOMAIN=yourdomain.com (optional - restricts recipient domains)
```

## Usage Example

```
jsonPOST /api/SendSecureEmail
{
    "to": "recipient@example.com",
    "subject": "Your Subject Here",
    "body": "Your email message content",
    "from": "sender@yourdomain.com",
    "apiKey": "your-secret-api-key"
}
```

## Additional Security Recommendations

Use Azure Key Vault for storing sensitive credentials instead of environment variables
Enable Application Insights for monitoring and alerting on suspicious activity
Set up Azure Front Door or Application Gateway for additional DDoS protection
Implement Azure AD authentication for even stronger security if internal use
Add request/response logging for audit trails
Consider using Azure Communication Services instead of SMTP for better Azure integration

The function returns appropriate HTTP status codes (400, 401, 429, 500) and minimal error information to prevent information leakage while still being useful for legitimate debugging.