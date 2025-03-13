using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ASD.SeedProjectNet8.Web.Controllers;

[ApiController]
[Route("api/[controller]/[action]")]
[Authorize]
public class BaseController : ControllerBase
{
    private ISender _sender;
    protected ISender Sender => _sender ??= HttpContext.RequestServices.GetService<ISender>();

}
