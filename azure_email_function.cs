using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net.Mail;
using System.Net;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using System.ComponentModel.DataAnnotations;

namespace SecureEmailFunction
{
    public class EmailRequest
    {
        [Required]
        [EmailAddress]
        public string To { get; set; }
        
        [Required]
        [StringLength(200, MinimumLength = 1)]
        public string Subject { get; set; }
        
        [Required]
        [StringLength(5000, MinimumLength = 1)]
        public string Body { get; set; }
        
        public string From { get; set; }
        
        [Required]
        public string ApiKey { get; set; }
    }

    public class RateLimitInfo
    {
        public DateTime LastRequest { get; set; }
        public int RequestCount { get; set; }
        public DateTime WindowStart { get; set; }
    }

    public static class SecureEmailFunction
    {
        private static readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());
        private static readonly string _validApiKey = Environment.GetEnvironmentVariable("EMAIL_API_KEY");
        private static readonly string _smtpHost = Environment.GetEnvironmentVariable("SMTP_HOST");
        private static readonly string _smtpUser = Environment.GetEnvironmentVariable("SMTP_USER");
        private static readonly string _smtpPass = Environment.GetEnvironmentVariable("SMTP_PASS");
        private static readonly int _smtpPort = int.Parse(Environment.GetEnvironmentVariable("SMTP_PORT") ?? "587");
        private static readonly string _allowedDomain = Environment.GetEnvironmentVariable("ALLOWED_DOMAIN");
        
        // Rate limiting: 10 requests per hour per IP
        private const int MAX_REQUESTS_PER_HOUR = 10;
        private const int RATE_LIMIT_WINDOW_MINUTES = 60;

        [FunctionName("SendSecureEmail")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            try
            {
                log.LogInformation("Email function triggered");

                // Get client IP for rate limiting
                string clientIp = GetClientIpAddress(req);
                
                // Check rate limiting
                if (!IsWithinRateLimit(clientIp))
                {
                    log.LogWarning($"Rate limit exceeded for IP: {clientIp}");
                    return new StatusCodeResult(429); // Too Many Requests
                }

                // Read and validate request
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                
                if (string.IsNullOrEmpty(requestBody))
                {
                    return new BadRequestObjectResult("Request body is required");
                }

                EmailRequest emailRequest;
                try
                {
                    emailRequest = JsonConvert.DeserializeObject<EmailRequest>(requestBody);
                }
                catch (JsonException)
                {
                    return new BadRequestObjectResult("Invalid JSON format");
                }

                // Validate request object
                var validationResults = ValidateEmailRequest(emailRequest);
                if (validationResults.Count > 0)
                {
                    return new BadRequestObjectResult(new { 
                        error = "Validation failed", 
                        details = validationResults 
                    });
                }

                // Verify API key
                if (!VerifyApiKey(emailRequest.ApiKey))
                {
                    log.LogWarning($"Invalid API key attempt from IP: {clientIp}");
                    return new UnauthorizedResult();
                }

                // Additional security validations
                if (!IsValidEmailDomain(emailRequest.To))
                {
                    return new BadRequestObjectResult("Email domain not allowed");
                }

                if (ContainsSuspiciousContent(emailRequest.Subject, emailRequest.Body))
                {
                    log.LogWarning($"Suspicious content detected from IP: {clientIp}");
                    return new BadRequestObjectResult("Content validation failed");
                }

                // Send email
                await SendEmailAsync(emailRequest, log);
                
                // Update rate limiting
                UpdateRateLimit(clientIp);
                
                log.LogInformation($"Email sent successfully to: {emailRequest.To}");
                return new OkObjectResult(new { message = "Email sent successfully" });
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Error occurred while sending email");
                return new StatusCodeResult(500);
            }
        }

        private static string GetClientIpAddress(HttpRequest req)
        {
            // Check for X-Forwarded-For header (common in load balancers)
            string xForwardedFor = req.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(xForwardedFor))
            {
                return xForwardedFor.Split(',')[0].Trim();
            }

            // Check for X-Real-IP header
            string xRealIp = req.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(xRealIp))
            {
                return xRealIp;
            }

            // Fallback to connection remote IP
            return req.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        }

        private static bool IsWithinRateLimit(string clientIp)
        {
            string cacheKey = $"rate_limit_{clientIp}";
            
            if (_cache.TryGetValue(cacheKey, out RateLimitInfo rateLimitInfo))
            {
                var now = DateTime.UtcNow;
                
                // Reset counter if window has passed
                if (now.Subtract(rateLimitInfo.WindowStart).TotalMinutes >= RATE_LIMIT_WINDOW_MINUTES)
                {
                    rateLimitInfo.RequestCount = 0;
                    rateLimitInfo.WindowStart = now;
                }
                
                return rateLimitInfo.RequestCount < MAX_REQUESTS_PER_HOUR;
            }
            
            return true; // First request from this IP
        }

        private static void UpdateRateLimit(string clientIp)
        {
            string cacheKey = $"rate_limit_{clientIp}";
            var now = DateTime.UtcNow;
            
            if (_cache.TryGetValue(cacheKey, out RateLimitInfo rateLimitInfo))
            {
                rateLimitInfo.RequestCount++;
                rateLimitInfo.LastRequest = now;
            }
            else
            {
                rateLimitInfo = new RateLimitInfo
                {
                    RequestCount = 1,
                    LastRequest = now,
                    WindowStart = now
                };
            }
            
            _cache.Set(cacheKey, rateLimitInfo, TimeSpan.FromMinutes(RATE_LIMIT_WINDOW_MINUTES));
        }

        private static List<string> ValidateEmailRequest(EmailRequest request)
        {
            var errors = new List<string>();
            var context = new ValidationContext(request);
            var results = new List<ValidationResult>();
            
            if (!Validator.TryValidateObject(request, context, results, true))
            {
                foreach (var result in results)
                {
                    errors.Add(result.ErrorMessage);
                }
            }
            
            return errors;
        }

        private static bool VerifyApiKey(string providedKey)
        {
            if (string.IsNullOrEmpty(_validApiKey) || string.IsNullOrEmpty(providedKey))
            {
                return false;
            }
            
            // Use time-constant comparison to prevent timing attacks
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(_validApiKey),
                Encoding.UTF8.GetBytes(providedKey)
            );
        }

        private static bool IsValidEmailDomain(string email)
        {
            if (string.IsNullOrEmpty(_allowedDomain))
            {
                return true; // No domain restriction
            }
            
            try
            {
                var mailAddress = new MailAddress(email);
                return mailAddress.Host.EndsWith(_allowedDomain, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private static bool ContainsSuspiciousContent(string subject, string body)
        {
            // List of suspicious patterns that might indicate spam or malicious content
            var suspiciousPatterns = new[]
            {
                @"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", // Script tags
                @"javascript:", // JavaScript URLs
                @"data:text/html", // Data URLs with HTML
                @"\b(?:viagra|cialis|lottery|inheritance|prince|nigeria)\b", // Common spam words
                @"urgent.{0,20}response.{0,20}required", // Urgent response patterns
                @"click.{0,10}here.{0,10}now", // Suspicious call-to-action
            };

            string combinedContent = $"{subject} {body}".ToLowerInvariant();
            
            foreach (var pattern in suspiciousPatterns)
            {
                if (Regex.IsMatch(combinedContent, pattern, RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }
            
            return false;
        }

        private static async Task SendEmailAsync(EmailRequest emailRequest, ILogger log)
        {
            using (var client = new SmtpClient(_smtpHost, _smtpPort))
            {
                client.EnableSsl = true;
                client.UseDefaultCredentials = false;
                client.Credentials = new NetworkCredential(_smtpUser, _smtpPass);
                client.Timeout = 30000; // 30 seconds timeout

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(emailRequest.From ?? _smtpUser),
                    Subject = emailRequest.Subject,
                    Body = emailRequest.Body,
                    IsBodyHtml = false // Prevent HTML injection
                };
                
                mailMessage.To.Add(emailRequest.To);
                
                // Add security headers
                mailMessage.Headers.Add("X-Mailer", "SecureAzureFunction");
                mailMessage.Headers.Add("X-Priority", "3");
                
                await client.SendMailAsync(mailMessage);
            }
        }
    }
}