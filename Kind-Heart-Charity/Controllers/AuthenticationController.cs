using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Kind_Heart_Charity.Models.Authentication.SignUp;
using Kind_Heart_Charity.Models.Authentication.Login;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Threading.Tasks;

public class AuthenticationController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;

    public AuthenticationController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    // GET: Authentication/Signin
    public IActionResult Signin()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Signin(LoginModel model)
    {
        if (ModelState.IsValid)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);
            if (result.Succeeded)
            {
                return RedirectToAction("Dashboard", "Dashboard"); // Redirect to dashboard on successful login
            }
            ModelState.AddModelError("", "Invalid login attempt");
        }
        return View(model);
    }

    // GET: Authentication/Signup
    public IActionResult Signup()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Signup(RegisterUser model)
    {
        if (ModelState.IsValid)
        {
            var user = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false); // Automatically sign in the user after registration
                return RedirectToAction(nameof(Signin)); // Redirect to signin page after successful registration
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
        }
        return View(model);
    }

    public async Task<IActionResult> Signout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction(nameof(Signin));
    }

    public IActionResult AccessDenied()
    {
        return View();
    }



    public IActionResult ExternalLink()
    {
        if (_signInManager.IsSignedIn(User))
        {
            // User is logged in, redirect to the external URL
            return Redirect("https://github.com/");
        }
        else
        {
            // User is not logged in, redirect to the login page
            return RedirectToAction("Signin", "Authentication"); // Replace with your actual login route
        }
    }

    // Other CRUD actions and methods can be added here as needed.
}
