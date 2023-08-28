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
using Microsoft.DotNet.MSIdentity.Shared;

namespace Kind_Heart_Charity.Controllers
{
    public class DashboardController : Controller
    {
        private readonly Kind_Heart_CharityContext _context;

        public DashboardController(Kind_Heart_CharityContext context)
        {
            _context = context;
        }

    

        [Authorize]
        public IActionResult Dashboard()
        {
            
            return View();
        }

        [Authorize]
        public async Task<IActionResult> Subscribe()
        {
            return _context.MailingLists != null ?
            View(await _context.MailingLists.ToListAsync()) :
            Problem("Entity set 'Kind_Heart_CharityContext.MailingLists' is null.");
        }


        [Authorize]
        public async Task<IActionResult> Payments()
        {
            return _context.payments != null ?
            View(await _context.payments.ToListAsync()) :
            Problem("Entity set 'Kind_Heart_CharityContext.payments' is null.");
        }






    }
}
