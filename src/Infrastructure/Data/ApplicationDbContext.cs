using System.Reflection;
using ASD.SeedProjectNet8.Application.Common.Interfaces;
using ASD.SeedProjectNet8.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace ASD.SeedProjectNet8.Infrastructure.Data;

public class ApplicationDbContext : DbContext, IApplicationDbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    public DbSet<TodoList> TodoLists => Set<TodoList>();

    public DbSet<TodoItem> TodoItems => Set<TodoItem>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());
    }
}
