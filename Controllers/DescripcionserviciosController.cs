using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using projecto_net.Models;

namespace projecto_net.Controllers
{
    public class DescripcionserviciosController : Controller
    {
        private readonly MercyDeveloperContext _context;

        public DescripcionserviciosController(MercyDeveloperContext context)
        {
            _context = context;
        }

        // GET: Descripcionservicios
        public async Task<IActionResult> Index()
        {
            var mercyDeveloperContext = _context.Descripcionservicios.Include(d => d.Servicio);
            return View(await mercyDeveloperContext.ToListAsync());
        }

        // GET: Descripcionservicios/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var descripcionservicio = await _context.Descripcionservicios
                .Include(d => d.Servicio)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (descripcionservicio == null)
            {
                return NotFound();
            }

            return View(descripcionservicio);
        }

        // GET: Descripcionservicios/Create
        public IActionResult Create()
        {
            ViewData["ServicioId"] = new SelectList(_context.Servicios, "Id", "Id");
            return View();
        }

        // POST: Descripcionservicios/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,Nombre,ServicioId")] Descripcionservicio descripcionservicio)
        {
            if (ModelState.IsValid) 
            {
                _context.Add(descripcionservicio);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            ViewData["ServicioId"] = new SelectList(_context.Servicios, "Id", "Id", descripcionservicio.ServicioId);
            return View(descripcionservicio);
        }

        // GET: Descripcionservicios/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var descripcionservicio = await _context.Descripcionservicios.FindAsync(id);
            if (descripcionservicio == null)
            {
                return NotFound();
            }
            ViewData["ServicioId"] = new SelectList(_context.Servicios, "Id", "Id", descripcionservicio.ServicioId);
            return View(descripcionservicio);
        }

        // POST: Descripcionservicios/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Nombre,ServicioId")] Descripcionservicio descripcionservicio)
        {
            if (id != descripcionservicio.Id)
            {
                return NotFound();
            }

            if (descripcionservicio.Id !=0 && descripcionservicio.Nombre !=null && descripcionservicio.ServicioId !=0)
            {
                try
                {
                    _context.Update(descripcionservicio);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!DescripcionservicioExists(descripcionservicio.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            ViewData["ServicioId"] = new SelectList(_context.Servicios, "Id", "Id", descripcionservicio.ServicioId);
            return View(descripcionservicio);
        }

        // GET: Descripcionservicios/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var descripcionservicio = await _context.Descripcionservicios
                .Include(d => d.Servicio)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (descripcionservicio == null)
            {
                return NotFound();
            }

            return View(descripcionservicio);
        }

        // POST: Descripcionservicios/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var descripcionservicio = await _context.Descripcionservicios.FindAsync(id);
            if (descripcionservicio != null)
            {
                _context.Descripcionservicios.Remove(descripcionservicio);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool DescripcionservicioExists(int id)
        {
            return _context.Descripcionservicios.Any(e => e.Id == id);
        }
    }
}
