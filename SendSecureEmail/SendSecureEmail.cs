using Azure.Communication.Email;
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
        private static readonly string _smtpFromEmail = Environment.GetEnvironmentVariable("SMTP_FROM_EMAIL") ?? "";
        private static readonly string _allowedDomain = Environment.GetEnvironmentVariable("ALLOWED_DOMAIN") ?? "";
        private static readonly string _communicationService = Environment.GetEnvironmentVariable("ACS_CONNECTION_STRING") ?? "";

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
                    const string logMessageRateLimitExceeded = "Rate limit exceeded for IP: {ClientIp}";
                    log.LogWarning(logMessageRateLimitExceeded, clientIp);
                    var resp = req.CreateResponse(HttpStatusCode.TooManyRequests);
                    await resp.WriteStringAsync("Too Many Requests");
                    return resp;
                }

                // Read and validate request
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();

                if (string.IsNullOrEmpty(requestBody))
                {
                    const string logMessageInvalidBody = "Invalid Email Body";
                    log.LogWarning(logMessageInvalidBody);
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
                    const string logMessageJsonError = "Error Parsing Email Body";
                    log.LogWarning(logMessageJsonError);
                    var resp = req.CreateResponse(HttpStatusCode.BadRequest);
                    await resp.WriteStringAsync("Invalid JSON format");
                    return resp;
                }

                // Validate request object
                var validationResults = ValidateEmailRequest(emailRequest);
                if (validationResults.Count > 0)
                {
                    const string logMessageValidationError = "Error Validating Email Request";
                    log.LogWarning(logMessageValidationError);
                    var resp = req.CreateResponse(HttpStatusCode.BadRequest);
                    await resp.WriteStringAsync(JsonSerializer.Serialize(new
                    {
                        error = "Validation failed",
                        details = validationResults
                    }));
                    return resp;
                }

                // Verify API key
                if (emailRequest != null && !VerifyApiKey(emailRequest.ApiKey))
                {
                    const string logMessageInvalidApiKey = "Invalid API key attempt from IP: {ClientIp}";
                    log.LogWarning(logMessageInvalidApiKey, clientIp);
                    var resp = req.CreateResponse(HttpStatusCode.Unauthorized);
                    await resp.WriteStringAsync("Unauthorized");
                    return resp;
                }

                // Additional security validations
                if (emailRequest != null && !IsValidEmailDomain(emailRequest.To))
                {
                    const string logMessageInvalidDomain = "Invalid Email Domain";
                    log.LogWarning(logMessageInvalidDomain);
                    var resp = req.CreateResponse(HttpStatusCode.BadRequest);
                    await resp.WriteStringAsync("Email domain not allowed");
                    return resp;
                }

                if (emailRequest != null && ContainsSuspiciousContent(emailRequest.Subject, emailRequest.Body))
                {
                    const string logMessageSuspiciousContent = "Suspicious content detected from IP: {ClientIp}";
                    log.LogWarning(logMessageSuspiciousContent, clientIp);
                    var resp = req.CreateResponse(HttpStatusCode.BadRequest);
                    await resp.WriteStringAsync("Content validation failed");
                    return resp;
                }

                // Send email
                if (emailRequest != null)
                {
                    await SendEmailAsync(emailRequest, log);
                }

                // Update rate limiting
                UpdateRateLimit(clientIp);

                if (emailRequest == null)
                {
                    const string logMessageNullRequest = "Email request is null";
                    log.LogError(logMessageNullRequest);
                    var resp = req.CreateResponse(HttpStatusCode.BadRequest);
                    await resp.WriteStringAsync("Email request cannot be null");
                    return resp;
                }

                const string logMessageSuccess = "Email sent successfully to: {Recipient}";
                log.LogInformation(logMessageSuccess, emailRequest.To);
                var okResp = req.CreateResponse(HttpStatusCode.OK);
                await okResp.WriteStringAsync(JsonSerializer.Serialize(new { message = "Email sent successfully" }));
                return okResp;
            }
            catch (Exception ex)
            {
                const string logMessageError = "Error occurred while sending email - {ErrorMessage}";
                log.LogError(ex, logMessageError, ex.Message);
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

        private static Task SendEmailAsync(EmailRequest emailRequest, ILogger log)
        {

            var emailClient = new EmailClient(_communicationService);

            var emailContent = new EmailContent(
                   emailRequest.Subject
             ){
                Html = $"From {emailRequest.From}<br /><br />{emailRequest.Body}"
            };

           var emailSendOperation = emailClient.SendAsync(Azure.WaitUntil.Completed, new EmailMessage(
                 _smtpFromEmail,
                emailRequest.To,
                emailContent
            ));

            log.LogInformation($"Email sent successfully. Status: {emailSendOperation.Status}");

            return Task.CompletedTask;
        }
    }
}
