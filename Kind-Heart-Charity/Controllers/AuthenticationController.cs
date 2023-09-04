using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Kind_Heart_Charity.Models.Authentication.SignUp;
using Kind_Heart_Charity.Models.Authentication.Login;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Kind_Heart_Charity.Models.Authentication.FacebookAuth;
using Facebook;
using Microsoft.EntityFrameworkCore;
using Kind_Heart_Charity.Data;
using Kind_Heart_Charity.Models;

public class AuthenticationController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly Kind_Heart_CharityContext _context;

    public AuthenticationController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, Kind_Heart_CharityContext context, RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _context = context;
        _roleManager = roleManager; 
    }

    // GET: Authentication/Signin
    //public IActionResult Signin()
    //{
    //    return View();
    //}

    public ActionResult Signin()
    {
        var fb = new FacebookClient();
        var loginUrl = fb.GetLoginUrl(new
        {
            client_id = "313166984588794",
            redirect_uri = "https://localhost:8080/Authentication/FacebookRedirect",
            scope = "public_profile,email"
        });
        ViewBag.Url = loginUrl;

        return View();
    }

    public ActionResult FacebookRedirect(string code)
    {
        var fb = new FacebookClient();
        dynamic result = fb.Get("/oauth/access_token", new
        {
            client_id = "313166984588794",
            client_secret = "2361755ce4844cee6cf3e871e96d3df5",
            redirect_uri = "https://localhost:8080/Authentication/FacebookRedirect",
            code = code

        });

        fb.AccessToken = result.access_token;

        dynamic me = fb.Get("/me?fields=name,email");
        string name = me.name;
        string email = me.email;
        return RedirectToAction("Signin");
    }

    //[HttpPost]
    //[ValidateAntiForgeryToken]
    //public async Task<IActionResult> Signin(LoginModel model)
    //{
    //    if (ModelState.IsValid)
    //    {
    //        var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);
    //        if (result.Succeeded)
    //        {
    //            return RedirectToAction("Dashboard", "Dashboard"); // Redirect to dashboard on successful login
    //        }
    //        ModelState.AddModelError("", "Invalid login attempt");
    //    }
    //    return View(model);
    //}


    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Signin(LoginModel model)
    {
        if (ModelState.IsValid)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                var userid = user.Id;
                var roleIdToCheck = "eb1b091f-688e-4727-b8c7-29c1ea79e6f0"; // Replace with the role ID to check
                var userroles = _context.UserRoles.ToList();
                // Check if the user has the specified role ID
                var userHasRole = _context.UserRoles.Any(ur => ur.UserId == userid && ur.RoleId == roleIdToCheck);

                // Check if the user has the "admin" role by comparing role IDs
                if (userHasRole) // Replace with the actual admin role ID
                {
                    return RedirectToAction("Dashboard", "Dashboard");
                }
                else
                {
                    return RedirectToAction("Index", "Home"); // Redirect to home for non-admin users
                }
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
    public async Task<IActionResult> Signup(UserWithRoleDTO model)
    {
        model.SelectedRole = "User";
        if (ModelState.IsValid)
        {
            var user = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
          
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false); // Automatically sign in the user after registration

                if (!string.IsNullOrEmpty(model.SelectedRole))
                {
                    await _userManager.AddToRoleAsync(user, model.SelectedRole);
                }

                return RedirectToAction("Signin");
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


    //public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
    //{
    //    if (remoteError != null)
    //    {
    //        // Handle error from the external provider
    //        return RedirectToAction("Signin"); // Redirect to login page with an error message
    //    }

    //    var info = await _signInManager.GetExternalLoginInfoAsync();
    //    if (info == null)
    //    {
    //        // External login information is not available
    //        return RedirectToAction("Signin"); // Redirect to login page with an error message
    //    }

    //    // Attempt to sign in the user with the external provider information
    //    var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
    //    if (result.Succeeded)
    //    {
    //        // User successfully signed in with the external provider
    //        return RedirectToAction("Index", "Home"); // Redirect to the home page
    //    }

    //    if (result.IsLockedOut)
    //    {
    //        // Handle locked out user
    //        return RedirectToAction("Lockout"); // Redirect to lockout page
    //    }
    //    else
    //    {
    //        // If the user doesn't have an account, prompt them to create one
    //        var loginModel = new LoginModel
    //        {
    //            Email = info.Principal.FindFirstValue(ClaimTypes.Email),
    //            ReturnUrl = returnUrl,
    //            LoginProvider = info.LoginProvider
    //        };

    //        return View("ExternalLoginConfirmation", loginModel);
    //    }

    //}



    //[HttpPost]
    //[AllowAnonymous]
    //[ValidateAntiForgeryToken]
    //public IActionResult ExternalLogin(string provider, string returnUrl = null)
    //{
    //    var redirectUrl = Url.Action("ExternalLoginCallback", "Authentication", new { ReturnUrl = returnUrl });
    //    var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
    //    return new ChallengeResult(provider, properties);
    //}


    // Other CRUD actions and methods can be added here as needed.
}
