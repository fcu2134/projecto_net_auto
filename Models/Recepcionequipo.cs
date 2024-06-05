using System;
using System.Collections.Generic;

namespace projecto_net.Models;

public partial class Recepcionequipo
{
    public int Id { get; set; }

    public int ServicioId { get; set; }

    public int ClienteId { get; set; }

    public DateTime? Fecha { get; set; }

    public int? TipoPc { get; set; }

    public string? Accesorio { get; set; }

    public string? MarcaPc { get; set; }

    public string? ModeloPc { get; set; }

    public string? Nserie { get; set; }

    public int? CapacidadRam { get; set; }

    public int? Tipoalmacenamiento { get; set; }

    public string? CapacidadAlmacenamiento { get; set; }

    public int? Tipogpu { get; set; }

    public string? Grafica { get; set; }

    public virtual Cliente Cliente { get; set; } = null!;

    public virtual Servicio Servicio { get; set; } = null!;
}
