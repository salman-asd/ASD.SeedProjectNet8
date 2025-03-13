using ASD.SeedProjectNet8.Application.Common.Models;
using ASD.SeedProjectNet8.Application.Identity.Commands;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ASD.SeedProjectNet8.Web.Controllers;

public class AuthController : BaseController
{
    private readonly IConfiguration _configuration;
    private readonly IHttpContextAccessor _context;
    private static readonly string RefreshTokenKey = "X-Refresh-Token";
    private static readonly string Authorization = nameof(Authorization);

    public AuthController(IConfiguration configuration, IHttpContextAccessor context)
    {
        _configuration = configuration;
        _context = context;
    }

    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] CreateAppUserCommand command, CancellationToken cancellationToken)
    {
        var result = await Sender.Send(command, cancellationToken);
        if (!result.Succeeded)
            return BadRequest(result);
        return Ok(result);
    }

    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequestCommand command, CancellationToken cancellationToken)
    {
        var response = await Sender.Send(command, cancellationToken);
        if (response == null)
            return Unauthorized("Invalid username or password.");

        SetRefreshTokenInCookie(response.RefreshToken, response.RefreshTokenExpiresOn);

        return Ok(response);
    }

    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [AllowAnonymous]
    public async Task<IActionResult> RefreshToken()
    {
        if (!_context.HttpContext.Request.Headers.TryGetValue(Authorization, out var authorizationHeader))
        {
            return Unauthorized();
        }
        var accessToken = authorizationHeader.ToString().Replace("Bearer ", "");

        if (!_context.HttpContext.Request.Cookies.TryGetValue(RefreshTokenKey, out var refreshToken))
        {
            throw new UnauthorizedAccessException("RefreshToken not found");
        }

        var authResponse = await Sender.Send(new RefreshTokenRequestCommand(refreshToken, accessToken));

        if (authResponse is null)
        {
            throw new UnauthorizedAccessException("RefreshToken not found");
        }

        SetRefreshTokenInCookie(authResponse.RefreshToken, authResponse.RefreshTokenExpiresOn);

        return Ok(authResponse);
    }

    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Logout()
    {
        if (_context.HttpContext.Request.Cookies.TryGetValue(RefreshTokenKey, out var refreshToken))
        {
            await Sender.Send(new LogoutRequestCommand(refreshToken));
        }

        SetRefreshTokenInCookie(string.Empty, DateTime.UtcNow.AddDays(-1));

        return Ok();
    }

    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordCommand command, CancellationToken cancellationToken)
    {
        var result = await Sender.Send(command, cancellationToken);
        if (!result.Succeeded)
            return BadRequest(result);
        return Ok(result);
    }

    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordCommand command, CancellationToken cancellationToken)
    {
        var result = await Sender.Send(command, cancellationToken);
        if (!result.Succeeded)
            return BadRequest(result);
        return Ok(result);
    }

    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordCommand command, CancellationToken cancellationToken)
    {
        var changePasswordCommand = new ChangePasswordCommand(command.OldPassword, command.NewPassword);
        var result = await Sender.Send(changePasswordCommand, cancellationToken);
        if (!result.Succeeded)
            return BadRequest(result);
        return Ok(result);
    }

    private void SetRefreshTokenInCookie(
        string refreshToken,
        DateTimeOffset expiresOn)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = expiresOn,
            Secure = true,
            //Secure = false,
            Path = "/",
            //SameSite = SameSiteMode.None,
            SameSite = SameSiteMode.Lax,
        };
        _context.HttpContext.Response.Cookies.Append(RefreshTokenKey, refreshToken, cookieOptions);
    }

    //[HttpGet]
    //[ProducesResponseType(StatusCodes.Status200OK)]
    //[ProducesResponseType(StatusCodes.Status404NotFound)]
    //public async Task<IActionResult> GetUserInfo( CancellationToken cancellationToken)
    //{
    //    var result = await Sender.Send(new GetUserInfoCommand(), cancellationToken);

    //    if (result == null)
    //        return Unauthorized("User not found");

    //    return Ok(result);
    //}


    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string email, [FromQuery] string token, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
        {
            return RedirectToErrorPage("Invalid confirmation link");
        }

        try
        {
            var result = await Sender.Send(new ConfirmEmailCommand(email, token), cancellationToken);
            if (!result.Succeeded)
            {
                return RedirectToErrorPage(result.Errors.First());
            }

            return RedirectToSuccessPage();
        }
        catch (Exception ex)
        {
            // Log the exception here
            return RedirectToErrorPage("An unexpected error occurred");
        }
    }

    private RedirectResult RedirectToErrorPage(string message)
    {
        var clientUrl = _configuration["ClientBaseUrl"];
        var confirmEmailRoute = _configuration["ConfirmUrl"];
        return Redirect($"{clientUrl}{confirmEmailRoute}/error?message={Uri.EscapeDataString(message)}");
    }

    private RedirectResult RedirectToSuccessPage()
    {
        var clientUrl = _configuration["ClientBaseUrl"];
        var confirmEmailRoute = _configuration["ConfirmUrl"];
        return Redirect($"{clientUrl}{confirmEmailRoute}/success");
    }


}


