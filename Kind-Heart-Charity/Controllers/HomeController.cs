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
using static Microsoft.EntityFrameworkCore.DbLoggerCategory;

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
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Signin", "Authentication"); // Replace with actual login action and controller
            }
            StripeConfiguration.ApiKey = "sk_test_51NgBVDEPVS0RJPUBKZmvKus2rWpb7O1wJgHYR0qLL8mSBCPMmQey1lFGOQtUEgzTmwO3a6EwdqGVhUK31GIm8lRl00s9r92m01";
            string username = User.Identity.Name;

            DateTime currentDate = DateTime.Now;
            var options = new PriceCreateOptions
            {
                UnitAmount = Convert.ToInt64(amount) * 100, // in cents
                Currency = "usd",
                ProductData = new PriceProductDataOptions
                {
                    Name = package
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
                SuccessUrl = DomainName + "PaymentConfirmation?Package=" + package + "&Amount=" + amount + "",
                CancelUrl = DomainName + "Index",
            };


            var service = new SessionService();
            var session = service.Create(sessionOptions);
            sessionId = session.Id;
            return Redirect(session.Url);
        }

        public async Task<IActionResult> PaymentConfirmation(string package, string amount)
        {
            string username = User.Identity.Name;
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
        public async Task<IActionResult> SendMessage([FromBody] MessageModel messageModel)
        {
            string name = messageModel.Name;
            string email = messageModel.Email;
            string message = messageModel.Message;
            // Configure your Gmail account
            string gmailUsername = "shabirhussain.6122@gmail.com";
            string gmailPassword = "hjzffrebuonaggii";

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
                // Send the email asynchronously
                await smtpClient.SendMailAsync(mailMessage);

                return Json(new { success = true });
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error sending email: " + ex.Message);
                return Json(new { success = false, message = "An error occurred while sending the email." });
            }





        }
    }
}