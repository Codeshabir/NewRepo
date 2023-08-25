﻿using Kind_Heart_Charity.Models;
using Microsoft.AspNetCore.Mvc;
using Stripe.Checkout;
using Stripe;
using System.Diagnostics;
using System.IO.Pipelines;
using Kind_Heart_Charity.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Kind_Heart_Charity.Models.Mailing;
using System.Text;
using System.Net.Mail;
using System.Net;

namespace Kind_Heart_Charity.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly Kind_Heart_CharityContext _context;

        public HomeController(ILogger<HomeController> logger, Kind_Heart_CharityContext context)
        {
            _logger = logger;
            _context = context;
        }

        public IActionResult Index()
        {
            List<DynamicPagesDBDTO> data = new List<DynamicPagesDBDTO>();
            _context.DynamicPages.Where(x => x.IsDeleted == false).ToList().ForEach(x => data.Add(new DynamicPagesDBDTO() { Id = x.Id, PageName = x.PageName, TotalRecords = 0, SectionName = x.SectionName }));
            ViewBag.AllPages = data;
            var SectionName = data.GroupBy(x => x.SectionName).Select(x => x.Key);
            ViewBag.SectionName = SectionName;
            var categories = _context.Categories.ToList();

            ViewBag.AllCategories = categories;
            return View();
        }



        [HttpPost]
        public IActionResult Subscribe(string email)
        {
            if (!string.IsNullOrWhiteSpace(email))
            {
                var mailingEntry = new MailingList
                {
                    Email = email,
                    CreatedDate = DateTime.Now
                };

                _context.MailingLists.Add(mailingEntry);
                _context.SaveChanges();

                TempData["SuccessMessage"] = "Your email has been successfully added to our mailing list!";
            }

            return RedirectToAction("Index");
        }

        public IActionResult DownloadEmails()
        {
            var mailingList = _context.MailingLists.ToList();
            var stringBuilder = new StringBuilder();

            foreach (var item in mailingList)
            {
                stringBuilder.AppendLine($"{item.Email},{item.CreatedDate}");
            }

            var csvData = stringBuilder.ToString();
            var bytes = Encoding.UTF8.GetBytes(csvData);

            return File(bytes, "text/csv", "mailing_list.csv");
        }



        string DomainName = "https://localhost:8080/Home/", sessionId;


        public IActionResult SubscribePackage(string package, decimal? amount)
        {
            StripeConfiguration.ApiKey = "sk_test_51N6bLAHOKzeMSUnWfEjZk3rYbqrwBCjmkRsCYtbnv3CjqNuZuCyVJvR6ZDtgTJIcmJcZprkV6HC2KQz6lW2xGrYZ00h6QMSO3T";

            string username = User.Identity.Name;
            DateTime currentDate = DateTime.Now;
            var options = new PriceCreateOptions
            {
                UnitAmount = Convert.ToInt64(amount) * 100, // in cents
                Currency = "usd",
                ProductData = new PriceProductDataOptions
                {
                    Name = "abc"
                }
            };

            var priceService = new PriceService();
            Price price = priceService.Create(options);

            // Create a new checkout session with the price as the line item
            var sessionOptions = new SessionCreateOptions
            {
                PaymentMethodTypes = new List<string>
                {
                    "card",
                },
                LineItems = new List<SessionLineItemOptions>
                {
                    new SessionLineItemOptions
                    {
                        Price = price.Id,
                        Quantity = 1,
                    },
                },
                Mode = "payment",
                SuccessUrl = DomainName + "PaymentConfirmation?Name=" + username + "&Package=" + package + "&Amount=" + amount + "",
                CancelUrl = DomainName + "Index",
            };


            var service = new SessionService();
            var session = service.Create(sessionOptions);
            sessionId = session.Id;
            return Redirect(session.Url);
        }

        public async Task<IActionResult> PaymentConfirmation(string username, string package, string amount)
        {
            Payments payments = new Payments(username, package, amount, 0, 0);

            if (ModelState.IsValid)
            {
                _context.Add(payments);
                await _context.SaveChangesAsync();
            }

            return Redirect("/Home/Index");
        }

        public IActionResult DownloadPaymentReports()
        {
            var mailingList = _context.payments.ToList();
            var stringBuilder = new StringBuilder();

            foreach (var item in mailingList)
            {
                stringBuilder.AppendLine($"{item.Name},{item.Package},{item.Amount},{item.CreatedDate}");
            }

            var csvData = stringBuilder.ToString();
            var bytes = Encoding.UTF8.GetBytes(csvData);

            return File(bytes, "text/csv", "payment_list.csv");
        }


        [HttpPost]
        public async Task<IActionResult> SendMessage(string name, string email, string message)
        {
            // Configure your Gmail account
            string gmailUsername = "shabirhussain.6122@gmail.com";
            string gmailPassword = "Mandhwani536@";

            // Set up the SMTP client
            var smtpClient = new SmtpClient("smtp.gmail.com")
            {
                Port = 587,
                Credentials = new NetworkCredential(gmailUsername, gmailPassword),
                EnableSsl = true, // Use SSL
            };

            // Compose the email
            var mailMessage = new MailMessage(email, "shabirhussain.6122@gmail.com")
            {
                Subject = "New Message from Contact Form",
                Body = $"Name: {name}\nEmail: {email}\nMessage:\n{message}",
            };

            try
            {
                // Send the email
                await smtpClient.SendMailAsync(mailMessage);
                return RedirectToAction("Index", "Home"); // Redirect to a success page
            }
            catch
            {
                // Handle errors and redirect to an error page
                return RedirectToAction("Error", "Home");
            }





        }
    }
}