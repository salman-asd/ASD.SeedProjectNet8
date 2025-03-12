﻿using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;

namespace ASD.SeedProjectNet8.Web.Middlewares;

public class GlobalExceptionHandlerMiddleware(
    ILogger<GlobalExceptionHandlerMiddleware> logger)
    : IExceptionHandler
{
    private const string CorrelationIdHeaderName = "X-Correlation-Id";
    private const string CorrelationId = "correlationId";
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        logger.LogError(exception, "Exception occured: {Message}", exception.Message);


        httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;

        var problemDetails = new ProblemDetails
        {
            Status = StatusCodes.Status500InternalServerError,
            Type = "https://datatracker.ietf.org/doc/html/rfc7231#section-6.6.1",
            Title = "Internal Server Error"
        };

        var env = httpContext.RequestServices.GetRequiredService<IWebHostEnvironment>();
        if (env.IsDevelopment())
        {
            //httpContext.Items.TryGetValue("correlationId", out var correlationId);
            httpContext.Request.Headers.TryGetValue(CorrelationIdHeaderName, out StringValues correlationId);
            problemDetails.Extensions[CorrelationId] = correlationId.FirstOrDefault() ?? httpContext.TraceIdentifier;
        }

        await httpContext.Response.WriteAsJsonAsync(problemDetails, cancellationToken).ConfigureAwait(false);

        return true;
    }
}
