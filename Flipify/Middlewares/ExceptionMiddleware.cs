using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Net;

namespace Flipify.Middlewares
{
    public class ExceptionMiddleware
    {
        private readonly RequestDelegate _next;

        public ExceptionMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context, ex);
            }
        }

        private Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            var statusCode = HttpStatusCode.InternalServerError;
            var message = "An unexpected error occurred.";

            if (exception is SecurityTokenExpiredException)
            {
                statusCode = HttpStatusCode.BadRequest;
                message = "Token has expired.";
            }
            else if (exception is UnauthorizedAccessException)
            {
                statusCode = HttpStatusCode.Unauthorized;
                message = "Unauthorized access.";
            }

            var response = new
            {
                error = message
            };

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)statusCode;
            return context.Response.WriteAsync(JsonConvert.SerializeObject(response));
        }
    }
}
