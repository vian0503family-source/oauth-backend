using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace Backend.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly HttpClient _http;

    public AuthController(IConfiguration config, IHttpClientFactory httpFactory)
    {
        _config = config;
        _http   = httpFactory.CreateClient();
    }

    // ── Step 1：前端來拿 Google 授權 URL ──
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

    // ── Step 2：前端拿到 auth_code 後送來這裡 ──
    // POST /api/auth/google-callback
    [HttpPost("google-callback")]
    public async Task<IActionResult> GoogleCallback([FromBody] CallbackRequest req)
    {
        // 2-1：用 auth_code 換 Google Access Token
        var tokenResponse = await ExchangeCodeForToken(req.Code);
        if (tokenResponse == null)
            return BadRequest(new { error = "無法換取 Google Token" });

        // 2-2：用 Google Access Token 取得使用者資料
        var userInfo = await GetGoogleUserInfo(tokenResponse.AccessToken);
        if (userInfo == null)
            return BadRequest(new { error = "無法取得使用者資料" });

        // 2-3：產生我們自己的 JWT
        var jwt = GenerateJwt(userInfo);

        // 2-4：寫入 HttpOnly Cookie
        Response.Cookies.Append("access_token", jwt, new CookieOptions
        {
            HttpOnly = true,
            Secure   = false, // 正式環境改 true
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

    // ── Step 3：前端確認登入狀態 ──
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

    // ── 登出 ──
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
        return JsonSerializer.Deserialize<GoogleTokenResponse>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }

    private async Task<GoogleUserInfo?> GetGoogleUserInfo(string accessToken)
    {
        _http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        var res = await _http.GetAsync("https://www.googleapis.com/oauth2/v2/userinfo");
        if (!res.IsSuccessStatusCode) return null;

        var json = await res.Content.ReadAsStringAsync();
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
            new Claim(JwtRegisteredClaimNames.Sub, user.Id)
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
    public string AccessToken  { get; set; } = "";
    public string? RefreshToken { get; set; }
}

public class GoogleUserInfo
{
    public string  Id      { get; set; } = "";
    public string  Email   { get; set; } = "";
    public string  Name    { get; set; } = "";
    public string? Picture { get; set; }
}