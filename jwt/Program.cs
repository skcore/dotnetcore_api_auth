using jwt.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

/* recommended to use the built-in JWT Bearer Middleware in
 * ASP.NET Core because it handles token validation and security concerns efficiently
 * Uncomment code 19-72 and comment code 86 to use the built-in JWT Bearer Middleware
 
 */
//get jwt settings from appsettings.json
//var configuration = builder.Configuration;
//var jwtSettings = configuration.GetSection("JwtSettings");

//builder.Services.AddAuthentication(options =>
//{
//    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
//    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

//}).AddJwtBearer(options =>
//{

//    options.TokenValidationParameters = new TokenValidationParameters
//    {
//        ValidateIssuer = true,
//        ValidateAudience = true,
//        ValidateLifetime = true,
//        ValidateIssuerSigningKey = true,
//        ValidIssuer = jwtSettings["Issuer"],
//        ValidAudience = jwtSettings["Audience"],
//        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]))

//    };

//    options.Events = new JwtBearerEvents
//    {
//        // Configure event handlers for token validation failures
//        OnAuthenticationFailed = context =>
//        {
//            // Handle token validation failures
//            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
//            context.Response.ContentType = "application/json";
//            return context.Response.WriteAsync(new
//            {
//                message = "Authentication failed. Invalid token.",
//                details = context.Exception.Message
//            }.ToString());
//        },

//        // Optional: Customize response when token is missing
//        OnChallenge = context =>
//        {
//            context.HandleResponse();
//            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
//            context.Response.ContentType = "application/json";
//            return context.Response.WriteAsync(new
//            {
//                message = "You are not authorized to access this resource."
//            }.ToString());
//        }

//    };

//});


//ASP.NET Core expects an authentication scheme to be specified
//when you call [Authorize] for role-based authorization
var configuration = builder.Configuration;
var jwtSettings = configuration.GetSection("JwtSettings");

builder.Services.AddAuthentication(options =>
{
options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

}).AddJwtBearer(options =>
{

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]))
    };

});

builder.Services.AddAuthorization(); // Add authorization services

builder.Services.AddControllers(); // Add MVC or API services


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseRouting();

// Use Custom JWT Middleware for Authentication
app.UseMiddleware<JwtMiddleWare>();

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});

app.Run();
