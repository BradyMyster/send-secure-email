using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecureEmailFunction
{
    public class EmailRequest
    {
        [Required]
        [EmailAddress]
        public required string To { get; set; }

        [Required]
        [StringLength(200, MinimumLength = 1)]
        public required string Subject { get; set; }

        [Required]
        [StringLength(5000, MinimumLength = 1)]
        public required string Body { get; set; }

        public string? From { get; set; }

        [Required]
        public required string ApiKey { get; set; }
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
        private static readonly string _validApiKey = Environment.GetEnvironmentVariable("EMAIL_API_KEY") ?? "";
        private static readonly string _smtpHost = Environment.GetEnvironmentVariable("SMTP_HOST") ?? "";
        private static readonly string _smtpUser = Environment.GetEnvironmentVariable("SMTP_USER") ?? "";
        private static readonly string _smtpPass = Environment.GetEnvironmentVariable("SMTP_PASS") ?? "";
        private static readonly int _smtpPort = int.Parse(Environment.GetEnvironmentVariable("SMTP_PORT") ?? "587");
        private static readonly string _allowedDomain = Environment.GetEnvironmentVariable("ALLOWED_DOMAIN") ?? "";

        // Rate limiting: 10 requests per hour per IP
        private const int MAX_REQUESTS_PER_HOUR = 10;
        private const int RATE_LIMIT_WINDOW_MINUTES = 60;


        // Fix for CA2254: Ensure that the logging message template is a constant string and does not vary between calls.

        [Function("SendSecureEmail")]
        public static async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequestData req,
             FunctionContext context)
        {
            var log = context.GetLogger("SendSecureEmail");
            try
            {            
                const string logMessageTriggered = "Email function triggered";
                log.LogInformation(logMessageTriggered);

                // Get client IP for rate limiting
                string clientIp = GetClientIpAddress(req);

                // Check rate limiting
                if (!IsWithinRateLimit(clientIp))
                {                    
                    log.LogWarning("Rate limit exceeded for IP: {ClientIp}", clientIp);
                    var resp = req.CreateResponse(HttpStatusCode.TooManyRequests);
                    await resp.WriteStringAsync("Too Many Requests");
                    return resp;
                }

                // Read and validate request
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();

                if (string.IsNullOrEmpty(requestBody))
                {
                    var resp = req.CreateResponse(HttpStatusCode.BadRequest);
                    await resp.WriteStringAsync("Request body is required");
                    return resp;
                }

                EmailRequest? emailRequest;
                try
                {
                    emailRequest = JsonSerializer.Deserialize<EmailRequest>(requestBody, s_readOptions); 
                }
                catch (JsonException)
                {
                    var resp = req.CreateResponse(HttpStatusCode.BadRequest);
                    await resp.WriteStringAsync("Invalid JSON format");
                    return resp;
                }

                // Validate request object
                var validationResults = ValidateEmailRequest(emailRequest);
                if (validationResults.Count > 0)
                {
                    var resp = req.CreateResponse(HttpStatusCode.BadRequest);
                    await resp.WriteStringAsync(JsonSerializer.Serialize(new
                    {
                        error = "Validation failed",
                        details = validationResults
                    }));
                    return resp;
                }

                // Verify API key
                if (emailRequest !=null && !VerifyApiKey(emailRequest.ApiKey))
                {                    
                    log.LogWarning("Invalid API key attempt from IP: {ClientIp}", clientIp);
                    var resp = req.CreateResponse(HttpStatusCode.Unauthorized);
                    await resp.WriteStringAsync("Unauthorized");
                    return resp;
                }

                // Additional security validations
                if (emailRequest !=null && !IsValidEmailDomain(emailRequest.To))
                {
                    var resp = req.CreateResponse(HttpStatusCode.BadRequest);
                    await resp.WriteStringAsync("Email domain not allowed");
                    return resp;
                }

                if (emailRequest !=null && ContainsSuspiciousContent(emailRequest.Subject, emailRequest.Body))
                {                  
                    log.LogWarning("Suspicious content detected from IP: {ClientIp}", clientIp);
                    var resp = req.CreateResponse(HttpStatusCode.BadRequest);
                    await resp.WriteStringAsync("Content validation failed");
                    return resp;
                }

                // Send email
                if (emailRequest !=null)
                {
                    await SendEmailAsync(emailRequest, log);
                }
               

                // Update rate limiting
                UpdateRateLimit(clientIp);

                if (emailRequest == null)
                {                    
                    log.LogError("Email request is null");
                    var resp = req.CreateResponse(HttpStatusCode.BadRequest);
                    await resp.WriteStringAsync("Email request cannot be null");
                    return resp;
                }

                log.LogInformation("Email sent successfully to: {Recipient}", emailRequest.To);
                var okResp = req.CreateResponse(HttpStatusCode.OK);
                await okResp.WriteStringAsync(JsonSerializer.Serialize(new { message = "Email sent successfully" }));
                return okResp;
            }
            catch (Exception ex)
            {                
                log.LogError(ex, "Error occurred while sending email");
                var resp = req.CreateResponse(HttpStatusCode.InternalServerError);
                await resp.WriteStringAsync("Internal Server Error");
                return resp;
            }
        }

        private static readonly JsonSerializerOptions s_readOptions = new()
        {
            PropertyNameCaseInsensitive = true
        };

        private static string GetClientIpAddress(HttpRequestData req)
        {
            // Check for X-Forwarded-For header (common in load balancers)
            if (req.Headers.TryGetValues("X-Forwarded-For", out var xForwardedFor))
            {
                var ip = xForwardedFor.FirstOrDefault();
                if (!string.IsNullOrEmpty(ip))
                    return ip.Split(',')[0].Trim();
            }

            // Check for X-Real-IP header
            if (req.Headers.TryGetValues("X-Real-IP", out var xRealIp))
            {
                var ip = xRealIp.FirstOrDefault();
                if (!string.IsNullOrEmpty(ip))
                    return ip;
            }

            // Fallback to connection remote IP
            return "unknown";
        }

        private static bool IsWithinRateLimit(string clientIp)
        {
            string cacheKey = $"rate_limit_{clientIp}";

            if (_cache.TryGetValue(cacheKey, out RateLimitInfo? rateLimitInfo) && rateLimitInfo != null)
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

            if (_cache.TryGetValue(cacheKey, out RateLimitInfo? rateLimitInfo) && rateLimitInfo !=null)
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

        private static List<string> ValidateEmailRequest(EmailRequest? request)
        {
            var errors = new List<string>();
            var context = request !=null? new ValidationContext(request) : null;
            var results = new List<ValidationResult>();

            if (context !=null && request !=null && !Validator.TryValidateObject(request, context, results, true))
            {
                foreach (var result in results)
                {
                    errors.Add(result.ErrorMessage??"");
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
            using var client = new SmtpClient(_smtpHost, _smtpPort);

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
