using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace jwt.Controllers
{
   
    [ApiController]
    [Route("api/[controller]")]
    public class SecureController : ControllerBase
    {
        // Allow all authenticated users, regardless of role
        [HttpGet]
        [Authorize]
        public IActionResult GetSecureData()
        {
            return Ok(new { message = "This is a secure endpoint" });
        }

        // Only users with the "admin" role can access this endpoint
        [Authorize(Roles = "admin")] // This protects the endpoint for Admin role
        [HttpGet("admin")]
        public IActionResult GetAdminData()
        {
            var username = User.Identity.Name;
            return Ok(new { message = $"Hello {username}, only admins can see this data!" });
        }

        // Only users with the "user" role can access this endpoint
        [Authorize(Roles = "user")]
        [HttpGet("user")]
        [Authorize]
        public IActionResult GetUserData()
        {
            var username = User.Identity.Name;
            return Ok(new { message = $"Hello {username}, this is user-level data!" });
        }

    }
}
