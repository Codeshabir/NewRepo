using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Kind_Heart_Charity.Data;
using Kind_Heart_Charity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

namespace Kind_Heart_Charity.Controllers
{
    public class Authentication : Controller
    {
        private readonly Kind_Heart_CharityContext _context;

        public Authentication(Kind_Heart_CharityContext context)
        {
            _context = context;
        }

        // GET: Authentication/Signup
        public IActionResult Signup()
        {
            return View();
        }

        // POST: Authentication/Signup
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.


     

        // This action initiates the Google authentication process
        public IActionResult Gmail()
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = "http://localhost:8080/Authentication/Signin/gmail/GoogleCallback", // Callback URL after authentication
                Items =
            {
                { "scheme", "Google" }
            }
            };

            return Challenge(properties, "Google");
        }

        // This action handles the callback from Google after successful authentication
        public IActionResult GoogleCallback()
        {
            // Handle the callback from Google, process the user information, and sign in the user.
            // Redirect the user to the desired page after successful authentication.
            return RedirectToAction("Index", "Home");
        }
    



    [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Signup(Auth auth)
        {
            auth.IsActive = 1;
            auth.Role = 1;
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(auth.Password);
            auth.Password = passwordHash;

            if (ModelState.IsValid)
            {
                _context.Add(auth);
                await _context.SaveChangesAsync();
                return Redirect("/Authentication/Signin");
            }
            return Redirect("/Authentication/Signin");
        }

        // GET: Authentication/Signin
        public IActionResult Signin()
        {
            return View();
        }

        // Post: Authentication/Signin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Signin(Auth auths)
        {
            if (auths.Email == null || _context.Auth == null)
            {
                return NotFound();
            }

            var succeeded = await _context.Auth.FirstOrDefaultAsync(authUser => authUser.Email == auths.Email);


            if (succeeded == null && !BCrypt.Net.BCrypt.Verify(auths.Password, succeeded.Password))
            {
                return View();
            }

            if(succeeded != null && BCrypt.Net.BCrypt.Verify(auths.Password, succeeded.Password))
            {
                ClaimsIdentity identity = null;
                bool isAuthenticated = false;

                identity = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.Name, succeeded.Email),
                    new Claim(ClaimTypes.Role, "Admin")
                }, CookieAuthenticationDefaults.AuthenticationScheme);

                isAuthenticated = true;

                if (isAuthenticated)
                {
                    var principal = new ClaimsPrincipal(identity);

                    var login = HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                    return RedirectToAction("Dashboard", "Dashboard");
                }

            }
                return View();
        }

        public IActionResult Signout()
        {
            var login = HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Redirect("/Authentication/Signin");
        }

        private bool AuthExists(int id)
        {
          return (_context.Auth?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
