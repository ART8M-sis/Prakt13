using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace UserManager.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]   
    public class ProfileController : ControllerBase
    {
        [HttpGet("me")]
        public IActionResult Me()
        {
            return Ok(new
            {
                UserId = User.FindFirstValue(ClaimTypes.NameIdentifier),
                Email = User.FindFirstValue(ClaimTypes.Email),
                FullName = User.FindFirstValue(ClaimTypes.Name),
                Roles = User.FindAll(ClaimTypes.Role).Select(r => r.Value)
            });
        }

        [HttpGet("admin-dashboard")]
        [Authorize(Roles = "Admin")]
        public IActionResult Admin() => Ok(new { SecretData = "Secret data" });
    }
}
