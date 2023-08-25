using Microsoft.EntityFrameworkCore;
using Kind_Heart_Charity.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Kind_Heart_Charity.Models.Mailing;

namespace Kind_Heart_Charity.Data
{
    public class Kind_Heart_CharityContext : IdentityDbContext<IdentityUser>
    {
        public Kind_Heart_CharityContext(DbContextOptions<Kind_Heart_CharityContext> options) : base(options)
        {
        }

        //public DbSet<Donations> Donations { get; set; }
        public DbSet<Payments> payments { get; set; }
        public DbSet<Auth> Auth { get; set; }
        public DbSet<DynamicPages> DynamicPages { get; set; }
        public DbSet<PagePost> PagePosts { get; set; }
        public DbSet<PostGalleryImages> PostGalleryImages { get; set; }
        public DbSet<Category> Categories { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<Order> Orders { get; set; }
        public DbSet<OrderItem> OrderItems { get; set; }
        public DbSet<ProductImage> ProductImage { get; set; }
        public DbSet<MailingList> MailingLists { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            SeedRoles(modelBuilder);

            // Your existing model configurations

            modelBuilder.Entity<Category>()
                .HasMany(c => c.Products)
                .WithOne(p => p.Category)
                .HasForeignKey(p => p.CategoryId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<Order>()
                .HasMany(o => o.OrderItems)
                .WithOne(oi => oi.Order)
                .HasForeignKey(oi => oi.Id)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<OrderItem>()
                .HasOne(oi => oi.Product)
                .WithMany()
                .HasForeignKey(oi => oi.ProductId)
                .OnDelete(DeleteBehavior.Cascade);
            modelBuilder.Entity<Product>()
                .Property(p => p.Price)
                .HasColumnType("decimal(18, 2)");

            modelBuilder.Entity<OrderItem>()
                .Property(oi => oi.Price)
                .HasColumnType("decimal(18, 2)");
        }


        private void SeedRoles(ModelBuilder modelBuilder)
        {   
            modelBuilder.Entity<IdentityRole>().HasData(
                new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName = "Admin" },
                new IdentityRole() { Name = "User", ConcurrencyStamp = "2", NormalizedName = "User" },
                new IdentityRole() { Name = "HR", ConcurrencyStamp = "3", NormalizedName = "HR" }
                );
        }
    }
}
