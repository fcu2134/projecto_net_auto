using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using projecto_net.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;


internal class Program
{
    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddControllersWithViews();
      
        builder.Services.AddDbContext<MercyDeveloperContext>(options =>

            options.UseMySql(builder.Configuration.GetConnectionString("conexion"),
                ServerVersion.Parse("10.4.32-mariadb")
            ));
      
            

        //se supone que aca van las configuraciones pa encryptar y no me sale na 



        //metodo para hacer un temporizaror de lo que easta haciendo ..
        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(Options =>
        {
            Options.LoginPath = "/Index/Login";
            Options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
        });
        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Home/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();
        app.UseAuthentication();

        app.UseAuthorization();

        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Login}/{action=Index}/{id?}");

        app.Run();
    }
}