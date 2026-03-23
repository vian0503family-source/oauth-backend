using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Backend.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly HttpClient _http;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IConfiguration config, IHttpClientFactory httpFactory,
                          ILogger<AuthController> logger)
    {
        _config = config;
        _http   = httpFactory.CreateClient();
        _logger = logger;
    }

    // GET /api/auth/google-login-url
    [HttpGet("google-login-url")]
    public IActionResult GetGoogleLoginUrl()
    {
        var clientId    = _config["Google:ClientId"];
        var redirectUri = _config["Google:RedirectUri"];
        var scope       = "openid email profile";

        var url = "https://accounts.google.com/o/oauth2/v2/auth" +
                  $"?client_id={clientId}" +
                  $"&redirect_uri={Uri.EscapeDataString(redirectUri!)}" +
                  $"&response_type=code" +
                  $"&scope={Uri.EscapeDataString(scope)}" +
                  $"&access_type=offline";

        return Ok(new { url });
    }

    // POST /api/auth/google-callback
    [HttpPost("google-callback")]
    public async Task<IActionResult> GoogleCallback([FromBody] CallbackRequest req)
    {
        var tokenResponse = await ExchangeCodeForToken(req.Code);
        if (tokenResponse == null)
            return BadRequest(new { error = "無法換取 Google Token" });

        _logger.LogInformation("AccessToken: {token}", tokenResponse.AccessToken);

        var userInfo = await GetGoogleUserInfo(tokenResponse.AccessToken);
        if (userInfo == null)
            return BadRequest(new { error = "無法取得使用者資料" });

        var jwt = GenerateJwt(userInfo);

        Response.Cookies.Append("access_token", jwt, new CookieOptions
        {
            HttpOnly = true,
            Secure   = false,
            SameSite = SameSiteMode.Lax,
            Expires  = DateTimeOffset.UtcNow.AddHours(1)
        });

        return Ok(new
        {
            message = "登入成功",
            user = new
            {
                userInfo.Name,
                userInfo.Email,
                userInfo.Picture
            }
        });
    }

    // GET /api/auth/me
    [Authorize]
    [HttpGet("me")]
    public IActionResult Me()
    {
        var name    = User.FindFirst(ClaimTypes.Name)?.Value;
        var email   = User.FindFirst(ClaimTypes.Email)?.Value;
        var picture = User.FindFirst("picture")?.Value;

        return Ok(new { name, email, picture });
    }

    // POST /api/auth/logout
    [HttpPost("logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete("access_token");
        return Ok(new { message = "已登出" });
    }

    // ════ Private Helpers ════

    private async Task<GoogleTokenResponse?> ExchangeCodeForToken(string code)
    {
        var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["code"]          = code,
            ["client_id"]     = _config["Google:ClientId"]!,
            ["client_secret"] = _config["Google:ClientSecret"]!,
            ["redirect_uri"]  = _config["Google:RedirectUri"]!,
            ["grant_type"]    = "authorization_code"
        });

        var res = await _http.PostAsync("https://oauth2.googleapis.com/token", body);
        if (!res.IsSuccessStatusCode) return null;

        var json = await res.Content.ReadAsStringAsync();
        _logger.LogInformation("Token Response: {json}", json);

        return JsonSerializer.Deserialize<GoogleTokenResponse>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }

    private async Task<GoogleUserInfo?> GetGoogleUserInfo(string accessToken)
    {
        var request = new HttpRequestMessage(
            HttpMethod.Get,
            "https://www.googleapis.com/oauth2/v2/userinfo"
        );
        request.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        var res = await _http.SendAsync(request);

        _logger.LogInformation("UserInfo Status: {status}", res.StatusCode);

        if (!res.IsSuccessStatusCode) return null;

        var json = await res.Content.ReadAsStringAsync();
        _logger.LogInformation("UserInfo Response: {json}", json);

        return JsonSerializer.Deserialize<GoogleUserInfo>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }

    private string GenerateJwt(GoogleUserInfo user)
    {
        var key   = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name,  user.Name),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim("picture",        user.Picture ?? ""),
            new Claim(JwtRegisteredClaimNames.Jti, user.Id)
        };

        var token = new JwtSecurityToken(
            issuer:             _config["Jwt:Issuer"],
            audience:           _config["Jwt:Audience"],
            claims:             claims,
            expires:            DateTime.UtcNow.AddHours(1),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

// ════ DTOs ════
public record CallbackRequest(string Code);

public class GoogleTokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = "";

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }
}

public class GoogleUserInfo
{
    public string  Id      { get; set; } = "";
    public string  Email   { get; set; } = "";
    public string  Name    { get; set; } = "";
    public string? Picture { get; set; }
}