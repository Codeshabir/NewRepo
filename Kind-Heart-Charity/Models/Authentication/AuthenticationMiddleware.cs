using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using Kind_Heart_Charity.Models.Authentication.SignUp;
using Kind_Heart_Charity.Models.Authentication.Login;

public class AuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SignInManager<IdentityUser> _signInManager;

    public AuthenticationMiddleware(RequestDelegate next, SignInManager<IdentityUser> signInManager)
    {
        _next = next;
        _signInManager = signInManager;
    }

    public async Task Invoke(HttpContext context)
    {
        var path = context.Request.Path.Value;

        if (path.Equals("/Login", System.StringComparison.OrdinalIgnoreCase) && context.Request.Method == "POST")
        {
            var loginModel = new LoginModel();

            await context.Request.BodyReader.ReadAsync(); // Read the request body
            var formData = context.Request.Form;

            loginModel.Email = formData["Username"];
            loginModel.Password = formData["Password"];

            // Perform the login logic
            var result = await _signInManager.PasswordSignInAsync(loginModel.Email, loginModel.Password, false, lockoutOnFailure: false);

            if (result.Succeeded)
            {
                // Redirect to the dashboard upon successful login
                context.Response.Redirect("/Dashboard");
                return;
            }
        }
        else if (path.Equals("/SignUp", System.StringComparison.OrdinalIgnoreCase) && context.Request.Method == "POST")
        {
            var registerUser = new RegisterUser();

            await context.Request.BodyReader.ReadAsync(); // Read the request body
            var formData = context.Request.Form;

            registerUser.Username = formData["Username"];
            registerUser.Email = formData["Email"];
            registerUser.Password = formData["Password"];

            // Perform the signup logic
            // You can use the UserManager to create a new user and add them to the database

            // Redirect to the dashboard upon successful signup
            context.Response.Redirect("/Dashboard");
            return;
        }

        await _next(context);
    }
}
