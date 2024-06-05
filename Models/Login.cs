using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.ComponentModel.DataAnnotations;

namespace projecto_net.Models
{
    public class Login
    {
        
      
        [DataType(DataType.EmailAddress)]
        [Required]
        public string? Correo { get; set; }


        [Required]
        public string? Password { get; set; }
    }
    
}