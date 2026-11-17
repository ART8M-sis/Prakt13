using Microsoft.AspNetCore.Identity;   // здесь живёт PasswordHasher - он входит в ASP.NET Core, ставить ничего не нужно
using System.Collections.Concurrent;
using UserManager.DTO;
using UserManager.Models;

namespace UserManager.Services
{
    public interface IAuthService
    {
        (bool ok, string? error) Register(RegisterRequest request);
        (string? token, AuthUser? user) Login(LoginRequest request);
    }

    public class AuthService : IAuthService
    {
        private static readonly string[] AllowedRoles = { "User", "Admin" };

        private readonly ConcurrentDictionary<string, AuthUser> _users = new();

        private readonly PasswordHasher<AuthUser> _hasher = new();

        private readonly ITokenService _tokenService;

        public AuthService(ITokenService tokenService) => _tokenService = tokenService;

        public (bool ok, string? error) Register(RegisterRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
                return (false, "Email and password are required.");

            if (request.Password.Length < 6 || !request.Password.Any(char.IsDigit))
                return (false, "Password must be at least 6 characters and contain a digit.");

            var roleName = string.IsNullOrWhiteSpace(request.Role) ? "User" : request.Role;
            if (!AllowedRoles.Contains(roleName))
                return (false, $"Unknown role '{roleName}'. Allowed: {string.Join(", ", AllowedRoles)}");

            var email = request.Email.Trim().ToLowerInvariant();

            var user = new AuthUser
            {
                Email = email,
                FirstName = request.FirstName,
                LastName = request.LastName,
                Role = roleName
            };
            user.PasswordHash = _hasher.HashPassword(user, request.Password);

            if (!_users.TryAdd(email, user))
                return (false, "User with this email already exists.");

            return (true, null);
        }

        public (string? token, AuthUser? user) Login(LoginRequest request)
        {
            var email = (request.Email ?? "").Trim().ToLowerInvariant();

            if (!_users.TryGetValue(email, out var user))
                return (null, null);

            var check = _hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password ?? "");
            if (check == PasswordVerificationResult.Failed)
                return (null, null);

            return (_tokenService.CreateToken(user), user);
        }
    }
}
