using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace jwt.Middleware
{
    public class JwtMiddleWare
    {
        private readonly RequestDelegate _next;
        private readonly string _secretKey;
        private readonly string _issuer;
        private readonly string _audience;

        public JwtMiddleWare(RequestDelegate next, IConfiguration configuration)
        {
            _next = next;
            _secretKey = configuration["JwtSettings:Key"];
            _issuer = configuration["JwtSettings:Issuer"];
            _audience = configuration["JwtSettings:Audience"];
        }

        public async Task InvokeAsync(HttpContext context)
        {

            if (context.Request.Path.StartsWithSegments("/api/auth/login"))
            {
                await _next(context);
                return;
            }

            // Check if the request has an Authorization header
            if (!context.Request.Headers.ContainsKey("Authorization"))
            {
                await UnauthorizedResponse(context, "Authorization header missing.");
                return;
            }

            var token = context.Request.Headers["Authorization"].ToString().Split(" ").Last();

            // Validate JWT token
            var principal = ValidateToken(token);
            if (principal == null)
            {
                await UnauthorizedResponse(context, "Invalid or expired JWT token.");
                return;
            }

            // Attach the user claims (principal) to HttpContext.User
            context.User = principal;

            // Call the next middleware in the pipeline
            await _next(context);
        }

        private ClaimsPrincipal ValidateToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_secretKey);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _issuer,
                    ValidAudience = _audience,
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };

                // Validate the token and return the claims principal
                var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                // Check for role claim
                var roleClaim = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

                return principal;
            }
            catch (SecurityTokenException ex)
            {
                // Token validation failed (invalid, expired, etc.)
                Console.WriteLine($"Token validation error: {ex.Message}");
                return null;
            }
        }

        private Task UnauthorizedResponse(HttpContext context, string message)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            return context.Response.WriteAsync(new
            {
                message = message
            }.ToString());
        }
    }

}
