using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserManager.DTO;
using UserManager.Services;

namespace UserManager.Controllers
{
    [ApiController]                
    [Route("api/[controller]")]       
    [AllowAnonymous]                   
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _auth;
        public AuthController(IAuthService auth) => _auth = auth;

        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterRequest request)
        {
            var (ok, error) = _auth.Register(request);
            if (!ok) return BadRequest(new { message = error });  
            return Ok(new { message = $"User {request.Email} registered." });
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            var (token, user) = _auth.Login(request);

            if (token == null || user == null)
                return Unauthorized(new { message = "Invalid email or password" });   

            var fullName = $"{user.FirstName} {user.LastName}".Trim();
            return Ok(new AuthResponse(token, user.Email, fullName, user.Role));
        }
    }
}
