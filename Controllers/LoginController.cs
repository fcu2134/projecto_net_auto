using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using projecto_net.Models;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;

namespace projecto_net.Controllers
{
    public class LoginController : Controller
    {  //uso el contexto de la base de datos para poder hacer el login 
        private readonly MercyDeveloperContext _context;

     

        public LoginController(MercyDeveloperContext context)
        {
            _context = context;
        }

        public IActionResult Registro()
        {
            return View(new Registro());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegistroAsync(Registro registro)
        {   //comprara que los datos no sean nulos
            if (registro.Correo == null || registro.Password == null)
            {
                ViewData["mensaje"] = "Correo y contraseña son obligatorios.";
                return View();
            }
            //realiza una busqueda en la base dedatos si el usuario ya exite si existe te saldra el error 
            var usuarioExistente = await _context.Usuarios.FirstOrDefaultAsync(u => u.Correo == registro.Correo);
            if (usuarioExistente != null)
            {
                ViewData["mensaje"] = "El correo ya está registrado.";
                return View();
            }

            
            
            //creo una lista en donde digo que sde subira ala base de datos 
            Usuario usuario = new Usuario()
            {
                Nombre = registro.Nombre,
                Apellido = registro.Apellido,
                Correo = registro.Correo,
                Password = registro.Password
            };
            //guarda los datos en la base de datos 
            await _context.Usuarios.AddAsync(usuario);
            await _context.SaveChangesAsync();
            //el id del usuario no puede ser 0 si fuese el caso saldra un error 
            if (usuario.Id != 0)
            {
                return RedirectToAction("Index", "Login");
            }
            else
            {
                ViewData["mensaje"] = "Hubo un error al registrar el usuario.";
                return View();
            }
        }

        public IActionResult Index()
        {
            return View(new Login());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(Login login, AuthenticationProperties Properties)
        {
            Usuario? usuario_encontrado = await _context.Usuarios.Where(u => u.Correo == login.Correo && u.Password == login.Password).FirstOrDefaultAsync();
            //basicamente esto es para comparar y ver si el usuario no existe si se equivoca saldra error 
            if (usuario_encontrado == null)
            {
                ViewData["mensaje"] = "Correo o contraseña incorrectos.";
                return View();
            }
            //esto es basicamente los validadores del parametros donde digo que me guarde los datos para despues llamarlo y hacer que aparezca en tu html principal o donde tu quieras 
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, usuario_encontrado.Nombre ?? string.Empty),
                new Claim(ClaimTypes.Email, usuario_encontrado.Correo ?? string.Empty),
                new Claim(ClaimTypes.Anonymous, usuario_encontrado.Password ?? string.Empty)
            };

            ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            AuthenticationProperties properties = new AuthenticationProperties();

            // Inicio de sesión
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                properties
            );

            return RedirectToAction("Index", "Home");
        }

        // Método para encriptar texto usando TripleDES
        public string EncryptString(string plainText, string key)
        {
            byte[] iv = new byte[8];
            using (var des = TripleDES.Create())
            {
                des.Key = Encoding.UTF8.GetBytes(key);
                des.IV = iv;
                var encryptor = des.CreateEncryptor();
                byte[] bytes = Encoding.UTF8.GetBytes(plainText);
                return Convert.ToBase64String(encryptor.TransformFinalBlock(bytes, 0, bytes.Length));
            }
        }

        // Métodoen donde desencrpitamos la clave usando 3des 
        public string DecryptString(string encryptedText, string key)
        {   //inicia la inicializacion del vector de inicializacion(iV)
            //esta linea crea un array de bytes en donde tiene una longitud de 8 llamado iv,es crucial para ciertos modos de operacion de cifrado simetrico
            byte[] iv = new byte[8];
            //usa un using de bloque para crear una instancia de algoritmo tripledes ,asegurando que se liberen adecuadamente una vez que se completa el cifrado.
            using (var des = TripleDES.Create())
            { //establecemos una clave y el iv para el cifrado 

                des.Key = Encoding.UTF8.GetBytes(key);
                des.IV = iv;
                //crea un cifrador para realizar la transformacion de cifrado 
                var decryptor = des.CreateDecryptor();
                //convierte un el texto plano en un array de bytes que pode usar 
                byte[] bytes = Convert.FromBase64String(encryptedText);

                //realizamos el cifrado y devuelve el resultado como una cadena base64
                return Encoding.UTF8.GetString(decryptor.TransformFinalBlock(bytes, 0, bytes.Length));
            }
        }
    }
}
