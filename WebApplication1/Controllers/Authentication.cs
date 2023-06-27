using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApplication1.Data;
using WebApplication1.Models;
using WebApplication1.Services.RefreshTokenServices;
using WebApplication1.Services.UserServices;
using BCryptNet = BCrypt.Net.BCrypt;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Authentication : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;
        private readonly IRefreshTokenService _refreshTokenService;

        public Authentication(IConfiguration configuration, IUserService userService, IRefreshTokenService refreshTokenService)
        {
            _configuration = configuration;
            _userService = userService;
            _refreshTokenService = refreshTokenService;
        }

        [HttpPost("signin")]
        public ActionResult<string> SignIn(UserDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var passwordHash = HashPassword(request.Password);
            request.Password = passwordHash;

            var newUser = new User 
            { 
                Password = request.Password,
                Name = request.Name 
            };


            var user = _userService.CreateUser(newUser);

            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken, user);

            return GenerateJwtToken(user.Id, user.Name);
        }

        [HttpPost("Login")]
        public ActionResult<string> Login(LoginUser request)
        {
            var response = _userService.GetUser(request.Id);
            var user = response.Result;
            if (user == null)
            {
                return BadRequest("User not found");
            }

            if (!VerifyPassword(request.Password, user.Password))
            {
                return BadRequest("Invalid password");
            }
            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken, user);

            return GenerateJwtToken(user.Id, user.Name);

        }


        [HttpPost("refresh")]
        public async Task<ActionResult<string>> RefreshToken(int Id)
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var result = _userService.GetUser(Id);
            var user = result.Result;
            if (user == null)
            {
                return BadRequest("User not found");
            }
            if (!user.RefreshToken.Token.Equals(refreshToken)) 
            {
                return Unauthorized("Invalid refresh token");
            }else if (user.RefreshToken.Expires < DateTime.Now)
            {
                return Unauthorized("Token expired");
            }

            string token = GenerateJwtToken(user.Id, user.Name);
            var newRefreshToken = GenerateRefreshToken();
            SetRefreshToken(newRefreshToken, user);

            return Ok(token);
        } 

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(30),
                Created = DateTime.Now
            };
            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newRefreshToken, User user)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires,

            };
            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            newRefreshToken.UserId = user.Id;
            _refreshTokenService.CreateRefreshToken(newRefreshToken);


        }
        private string GenerateJwtToken(int userId, string UserName)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                new Claim(ClaimTypes.Name, UserName),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings")["Token"]));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                claims : claims,
                 expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials
            ); 

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

        private string HashPassword(string password)
        {
            // Generate a salt for the password hash
            string salt = BCryptNet.GenerateSalt();

            // Hash the password using BCrypt with the generated salt
            string hashedPassword = BCryptNet.HashPassword(password, salt);

            // Return the hashed password
            return hashedPassword;
        }
        private bool VerifyPassword(string password, string hashedPassword)
        {
            return BCryptNet.Verify(password, hashedPassword);
        }
    }
}
