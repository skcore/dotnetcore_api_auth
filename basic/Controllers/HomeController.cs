using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace basic.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class HomeController : ControllerBase
    {
        [HttpGet("admin")]
        [Authorize(Roles ="Admin")]
        public IActionResult Admin()
        {
            return Ok("Hello Admin! You are authorized.");
        }
        [HttpGet("hr")]
        [Authorize(Policy = "HRDepartment")]
        public IActionResult HRPage()
        {
            return Ok("Hello HR Department! You are authorized.");
        }
        [HttpGet("public")]
        public IActionResult PublicPage()
        {
            return Ok("Hello Public! Anyone can access this page.");
        }
    }
}
