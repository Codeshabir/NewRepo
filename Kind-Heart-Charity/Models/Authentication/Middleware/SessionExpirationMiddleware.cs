using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

public class SessionExpirationMiddleware
{
    private readonly RequestDelegate _next;

    public SessionExpirationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        // Check if the user is authenticated
        if (!context.User.Identity.IsAuthenticated)
        {
            // If not authenticated, redirect to the login page
            context.Response.Redirect("/Authentication/Signin");
            return;
        }

        await _next(context);
    }
}
