
namespace projecto_net.Models
{
    public partial class Usuario
    {
        public int Id { get; set; }
        public string? Nombre { get; set; }  
        public string? Apellido { get; set; }
        public string? Correo { get; set; } = null!;

        public string? Password { get; set; }
        public virtual ICollection<Servicio> Servicios { get; set; } = new List<Servicio>();
     
    }
}

