using System.Security.Claims;
using System.Text;

namespace basic.Middleware
{
    public class BasicAuthMiddleware
    {
        private readonly RequestDelegate _next;
        public BasicAuthMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.Request.Headers.ContainsKey("Authorization"))
            {
                var authHeader = context.Request.Headers["Authorization"].ToString();
                if (authHeader.StartsWith("Basic", StringComparison.OrdinalIgnoreCase))
                {
                    var token = authHeader.Substring("Basic ".Length).Trim();
                    var credentialString = Encoding.UTF8.GetString(Convert.FromBase64String(token));
                    var credentials = credentialString.Split(':');
                    var username = credentials[0];
                    var password = credentials[1];

                    // Validate username and password (hardcoded for this example)
                    if (ValidateCredentials(username, password))
                    {
                        var claims = new List<Claim>
                        {
                        new Claim(ClaimTypes.Name,username),
                        new Claim(ClaimTypes.Email, $"{username}@gtcore.com"),
                        new Claim(ClaimTypes.Role, "Admin"),
                        new Claim("Department", "HR")

                        };

                        var identity = new ClaimsIdentity(claims, "Basic");
                        var principal = new ClaimsPrincipal(identity);
                        context.User = principal;
                    }
                }

                await _next(context);
            }
        }
        private bool ValidateCredentials(string username, string password)
        {
            // Hardcoded validation for demo purposes
            return username == "admin" && password == "admin";
        }
    }
}
