using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Kind_Heart_Charity.Data;
using Kind_Heart_Charity.Models;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace Kind_Heart_Charity.Controllers
{
    [Authorize] // Apply Authorize attribute at the controller level
    public class UserController : Controller
    {
        private readonly Kind_Heart_CharityContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(Kind_Heart_CharityContext context, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<IActionResult> GetUsers()
        {
            var users = await _context.Users.ToListAsync();

            var usersWithRoles = new List<UserWithRoleDTO>();
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                var role = roles.FirstOrDefault();

                var userWithRole = new UserWithRoleDTO
                {
                    UserId = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    Role = role,
                    RolesList = roles.ToList() // Populate the roles list
                };

                usersWithRoles.Add(userWithRole);
            }

            return View(usersWithRoles);
        }

        public IActionResult CreateUser()
        {
            var roles = _roleManager.Roles.ToList();
            ViewBag.Roles = roles;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> CreateUser(UserWithRoleDTO model)
        {
            if (ModelState.IsValid)
            {
                var user = new IdentityUser { UserName = model.UserName };
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    if (!string.IsNullOrEmpty(model.SelectedRole))
                    {
                        await _userManager.AddToRoleAsync(user, model.SelectedRole);
                    }

                    return RedirectToAction(nameof(Index));
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            var roles = _roleManager.Roles.ToList();
            ViewBag.Roles = roles;
            return View(model);
        }

        // Add Edit, Delete, and Details actions similar to Create

        // ...



        // ROLE CRUD

        // GET: UserController/GetRoles
        public IActionResult GetRoles()
        {
            var roles = _roleManager.Roles.ToList();
            return View(roles);
        }

        // GET: UserController/CreateRole
        public IActionResult CreateRole()
        {
            return View();
        }

        // POST: UserController/CreateRole
        [HttpPost]
        public async Task<IActionResult> CreateRole(string Name)
        {
            if (!string.IsNullOrWhiteSpace(Name))
            {
                var result = await _roleManager.CreateAsync(new IdentityRole(Name));
                if (result.Succeeded)
                {
                    return RedirectToAction(nameof(GetRoles));
                }
            }
            ModelState.AddModelError("", "Role creation failed.");
            return View();
        }


    }
}
