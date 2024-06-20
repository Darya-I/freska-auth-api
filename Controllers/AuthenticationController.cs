using Auth_API.Models.DTOs;
using Auth_API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using RestSharp;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;


namespace Auth_API.Controllers
{
    [Route("api/auth/[controller]")]                             // api/authentication
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;

        public AuthenticationController(                    //конструктор
           UserManager<IdentityUser> userManager,
           IConfiguration configuration
           )
        {

            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("Authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] UserLoginRequestDTO loginRequest)
        {
            var user = await _userManager.FindByEmailAsync(loginRequest.Email);

            if (user == null)
            {
                return Unauthorized(new AuthResult
                {
                    Errors = new List<string> { "User not found" },
                    Result = false
                });
            }

            var signInResult = await _userManager.CheckPasswordAsync(user, loginRequest.Password);

            if (!signInResult)
            {
                return Unauthorized(new AuthResult
                {
                    Errors = new List<string> { "Invalid credentials" },
                    Result = false
                });
            }

            var jwtToken = GenerateJwtToken(user);

            return Ok(new AuthResult
            {
                Token = jwtToken,
                Result = true
            });
        }


        [HttpPost]
        [Route("Registration")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDTO requestDTO)
        {
            if (ModelState.IsValid)
            {
                var userExist = await _userManager.FindByEmailAsync(requestDTO.Email);
                if (userExist != null)
                {
                    return BadRequest(new AuthResult
                    {
                        Result = false,
                        Errors = new List<string> { "Почта уже существует, email already exist" }
                    });
                }

                var newUser = new IdentityUser
                {
                    Email = requestDTO.Email,
                    UserName = requestDTO.Email,
                    EmailConfirmed = false
                };

                var isCreated = await _userManager.CreateAsync(newUser, requestDTO.Password);

                if (isCreated.Succeeded)
                {
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                    var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                    var callbackUrl = Url.Action("ConfirmEmail", "Authentication",
                        new { userId = newUser.Id, code = encodedToken }, Request.Scheme);

                    var emailBody = $"Пожалуйста, подтвердите почту: <a href='{callbackUrl}'> Подтвердить почту </a>";

                    var emailSent = SendEmail(emailBody, newUser.Email);

                    if (emailSent)
                    {
                        return Ok("Подтвердите почту в письме, которое мы отправили");
                    }
                    else
                    {
                        return Ok("Пожалуйста, запросите подтверждающую ссылку");
                    }
                }
                else
                {
                    return BadRequest(new AuthResult
                    {
                        Errors = new List<string> { "Ошибка сервера, server error" },
                        Result = false
                    });
                }
            }

            return BadRequest();

        }

        [Route("ConfirmEmail")]
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
            {
                return BadRequest(new AuthResult
                {
                    Errors = new List<string> { "Invalid email confirmation URL" },
                    Result = false
                });
            }

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return BadRequest(new AuthResult
                {
                    Errors = new List<string> { "Invalid email parameters" },
                    Result = false
                });
            }

            // Декодируем токен перед его использованием
            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);

            if (result.Succeeded)
            {
                user.EmailConfirmed = true;
                var updateResult = await _userManager.UpdateAsync(user);

                if (updateResult.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, "User");
                    return Ok("Your email has been successfully confirmed.");
                }
                else
                {
                    return BadRequest(new AuthResult
                    {
                        Errors = new List<string> { "Error updating user" },
                        Result = false
                    });
                }
            }

            return BadRequest(new AuthResult
            {
                Errors = new List<string> { "Invalid email confirmation token" },
                Result = false
            });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDTO loginRequest)
        {
            if (ModelState.IsValid)
            {
                // check if the user exist, проверьте, существует ли пользователь
                var existing_user = await _userManager.FindByEmailAsync(loginRequest.Email);
                if (existing_user == null)
                {
                    return BadRequest(new AuthResult
                    {
                        Errors = new List<string>()
                        {
                            "недопустимые данные, invalid payload"
                        },
                        Result = false
                    });
                }

                // теперь, если пользователь существует, проверяется подтверждена ли почта

                if (!existing_user.EmailConfirmed)
                {
                    return BadRequest(new AuthResult
                    {
                        Errors = new List<string>()
                        {
                            "Email needs to be confirmed, почта не подтверждена"
                        },
                        Result = false
                    });
                }

                var isCorrect = await _userManager.CheckPasswordAsync(existing_user, loginRequest.Password);
                if (!isCorrect)
                {
                    return BadRequest(new AuthResult
                    {
                        Errors = new List<string>()
                        {
                            "Invalid credentials, неверные данные"
                        },
                        Result = false
                    });
                }

                var jwtToken = GenerateJwtToken(existing_user);

                return Ok(new AuthResult
                {
                    Token = jwtToken,
                    Result = true
                });
            }

            return BadRequest(new AuthResult
            {
                Errors = new List<string>
                {
                    "Недопустимые данные, invalid payload"
                },
                Result = false
            });
        }

        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();



            var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value); 

            // token description, описание токена

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Email, value:user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
                }),

                Expires = DateTime.Now.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);

        }

        private bool SendEmail(string body, string email)
        {
            var apiUrl = "https://api.mailopost.ru/v1/";
            var client = new RestClient(apiUrl);

            string apiKey = _configuration.GetSection("EmailConfig")["API_KEY"];
            string authorizationHeaderValue = "Bearer " + apiKey;

            var request = new RestRequest("email/messages", Method.Post);
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization", authorizationHeaderValue);

            var emailData = new
            {
                from_email = "freskastore@yandex.ru",
                from_name = "freska test",
                to = email,
                subject = "test",
                text = body,
                html = "<h1> TEST </h1>" + body,
                smtp_headers = new { Client_Id = "123" }
            };

            string jsonBody = JsonConvert.SerializeObject(emailData);

            request.AddParameter("application/json", jsonBody, ParameterType.RequestBody);

            var response = client.Execute(request);
            if (response.IsSuccessful)
            {
                return true;
            }
            else
                return false;
        }

    }
}
