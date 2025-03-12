using ASD.SeedProjectNet8.Application.Identity.Commands;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ASD.SeedProjectNet8.Web.Controllers;

public class AuthController : BaseController
{
    private readonly IConfiguration _configuration;

    public AuthController(IConfiguration configuration)
    {
        _configuration = configuration;
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
        return Ok(response);
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


