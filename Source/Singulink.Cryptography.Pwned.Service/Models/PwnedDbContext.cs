using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.EntityFrameworkCore;

namespace Singulink.Cryptography.Pwned.Service.Models;

public class PwnedDbContext : DbContext
{
    public DbSet<Password> Passwords { get; init; }

    public PwnedDbContext(DbContextOptions<PwnedDbContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Password>(entity => {
            entity.Property(e => e.Hash)
                .HasColumnType("char(40)")
                .IsRequired();

            entity.HasKey(entity => entity.Hash);
        });

        base.OnModelCreating(modelBuilder);
    }
}
