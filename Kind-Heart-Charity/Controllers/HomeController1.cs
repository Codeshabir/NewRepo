using Microsoft.AspNetCore.Mvc;

namespace Kind_Heart_Charity.Controllers
{
    public class HomeController1 : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
