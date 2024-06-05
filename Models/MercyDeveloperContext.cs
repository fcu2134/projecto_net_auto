using Microsoft.EntityFrameworkCore;

namespace projecto_net.Models;

public partial class MercyDeveloperContext : DbContext
{
    public MercyDeveloperContext()
    {
       
    }

    public MercyDeveloperContext(DbContextOptions<MercyDeveloperContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Cliente> Clientes { get; set; }

    public virtual DbSet<Descripcionservicio> Descripcionservicios { get; set; }

    public virtual DbSet<Recepcionequipo> Recepcionequipos { get; set; }

    public virtual DbSet<Servicio> Servicios { get; set; }

    public virtual DbSet<Usuario> Usuarios { get; set; }
    public Task Usuario { get; internal set; }
   

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured) { }

     
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder
            .UseCollation("utf8_general_ci")
            .HasCharSet("utf8");

        modelBuilder.Entity<Cliente>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("cliente");

            entity.Property(e => e.Id).HasColumnType("int(11)");
            entity.Property(e => e.Apellido).HasMaxLength(45);
            entity.Property(e => e.Correo).HasMaxLength(45);
            entity.Property(e => e.Direccion).HasMaxLength(30);
            entity.Property(e => e.Estado)
                .HasComment("0:Inactivo ; 1:Activo")
                .HasColumnType("int(11)");
            entity.Property(e => e.Nombre).HasMaxLength(45);
            entity.Property(e => e.Telefono).HasMaxLength(45);
        });

        modelBuilder.Entity<Descripcionservicio>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("descripcionservicio");

            entity.HasIndex(e => e.ServicioId, "fk_descripcionservicio_Servicio1_idx");

            entity.Property(e => e.Id)
                .ValueGeneratedNever()
                .HasColumnType("int(11)")
                .HasColumnName("id");
            entity.Property(e => e.Nombre)
                .HasMaxLength(45)
                .HasColumnName("nombre");
            entity.Property(e => e.ServicioId)
                .HasColumnType("int(11)")
                .HasColumnName("Servicio_Id");

            entity.HasOne(d => d.Servicio).WithMany(p => p.Descripcionservicios)
                .HasForeignKey(d => d.ServicioId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("fk_descripcionservicio_Servicio1");
        });

        modelBuilder.Entity<Recepcionequipo>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("recepcionequipo");

            entity.HasIndex(e => e.ClienteId, "fk_RecepcionEquipo_Cliente1_idx");

            entity.HasIndex(e => e.ServicioId, "fk_RecepcionEquipo_Servicio1_idx");

            entity.Property(e => e.Id)
                .ValueGeneratedNever()
                .HasColumnType("int(11)")
                .HasColumnName("id");
            entity.Property(e => e.Accesorio)
                .HasMaxLength(400)
                .HasColumnName("accesorio");
            entity.Property(e => e.CapacidadAlmacenamiento)
                .HasMaxLength(60)
                .HasColumnName("capacidadAlmacenamiento");
            entity.Property(e => e.CapacidadRam)
                .HasColumnType("int(11)")
                .HasColumnName("capacidadRam");
            entity.Property(e => e.ClienteId)
                .HasColumnType("int(11)")
                .HasColumnName("Cliente_Id");
            entity.Property(e => e.Fecha)
                .HasColumnType("datetime")
                .HasColumnName("fecha");
            entity.Property(e => e.Grafica)
                .HasMaxLength(60)
                .HasColumnName("grafica");
            entity.Property(e => e.MarcaPc)
                .HasMaxLength(60)
                .HasColumnName("marcaPc");
            entity.Property(e => e.ModeloPc)
                .HasMaxLength(60)
                .HasColumnName("modeloPc");
            entity.Property(e => e.Nserie).HasMaxLength(100);
            entity.Property(e => e.ServicioId)
                .HasColumnType("int(11)")
                .HasColumnName("Servicio_Id");
            entity.Property(e => e.TipoPc)
                .HasColumnType("int(11)")
                .HasColumnName("tipoPc");
            entity.Property(e => e.Tipoalmacenamiento).HasColumnType("int(11)");
            entity.Property(e => e.Tipogpu)
                .HasColumnType("int(11)")
                .HasColumnName("tipogpu");

            entity.HasOne(d => d.Cliente).WithMany(p => p.Recepcionequipos)
                .HasForeignKey(d => d.ClienteId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("fk_RecepcionEquipo_Cliente1");

            entity.HasOne(d => d.Servicio).WithMany(p => p.Recepcionequipos)
                .HasForeignKey(d => d.ServicioId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("fk_RecepcionEquipo_Servicio1");
        });

        modelBuilder.Entity<Servicio>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("servicio");

            entity.HasIndex(e => e.UsuarioId, "fk_Servicio_Usuario_idx");

            entity.Property(e => e.Id).HasColumnType("int(11)");
            entity.Property(e => e.Estado)
                .HasComment("0:Inactivo ; 1: Activo")
                .HasColumnType("int(11)");
            entity.Property(e => e.Nombre).HasMaxLength(60);
            entity.Property(e => e.Precio).HasColumnType("int(11)");
            entity.Property(e => e.Sku).HasMaxLength(50);
            entity.Property(e => e.UsuarioId).HasColumnType("int(11)");

            entity.HasOne(d => d.Usuario).WithMany(p => p.Servicios)
                .HasForeignKey(d => d.UsuarioId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("fk_Servicio_Usuario");
        });

        modelBuilder.Entity<Usuario>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("usuario");
    
            entity.Property(e => e.Id).HasColumnType("int(11)");
            entity.Property(e => e.Apellido).HasMaxLength(45);
            entity.Property(e => e.Correo).HasMaxLength(45);
            entity.Property(e => e.Nombre).HasMaxLength(45);
            entity.Property(e => e.Password).HasMaxLength(45);
        });

        OnModelCreatingPartial(modelBuilder);
    }

  
    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
