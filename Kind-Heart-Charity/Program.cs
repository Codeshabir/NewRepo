﻿using Kind_Heart_Charity.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Stripe;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// for Entity Framework
builder.Services.AddDbContext<Kind_Heart_CharityContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("Kind_Heart_CharityContext")));

builder.Services.AddControllersWithViews();

// for Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<Kind_Heart_CharityContext>()
    .AddDefaultTokenProviders();

// Adding Cookies-based Authentication for Identity
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Authentication/Signin/"; // Update this path to your login page
    });


//builder.Services.AddAuthentication()
//   .AddFacebook(options =>
//   {
//       options.AppId = "313166984588794"; // Your Facebook App ID
//       options.AppSecret = "2361755ce4844cee6cf3e871e96d3df5"; // Your Facebook App Secret
//   });



builder.Services.AddSession(options =>
{
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseSession();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
