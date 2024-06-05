using System.ComponentModel.DataAnnotations;

namespace projecto_net.Models
{
    public class Registro
    {
        [Required(ErrorMessage = "que te crees, no tienes nombre?")]
        public string? Nombre { get; set; } = null!;
        [Required(ErrorMessage = "y tu apellido ?")]
        public string Apellido { get; set; } = null!;
        [Required(ErrorMessage = "El campo correo es requerido.")]
        [EmailAddress(ErrorMessage = "Correo inválido")]
        [DataType(DataType.EmailAddress)]
        public string? Correo { get; set; }

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        [DataType(DataType.Password)]
        public string? Password { get; set; }
    }
}
