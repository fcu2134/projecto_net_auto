using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace projecto_net.Models;

public partial class Cliente
{ //esto son los modelos de las tablas , aca puedes agregar validadores o requirimientos por ejemplo 
    public int Id { get; set; }
    [Required]  
    public string Nombre { get; set; } = null!;

    public string Apellido { get; set; } = null!;

    public string Correo { get; set; } = null!;

    public string? Telefono { get; set; }

    public string? Direccion { get; set; }

    /// <summary>
    /// 0:Inactivo ; 1:Activo
    /// </summary>
    public int Estado { get; set; }

    public virtual ICollection<Recepcionequipo> Recepcionequipos { get; set; } = new List<Recepcionequipo>();
}
