using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Kind_Heart_Charity.Models
{
    public class Category
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public List<Product> Products { get; set; }
    }

    public class Product
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public decimal Price { get; set; }
        public string Description { get; set; }
        public int CategoryId { get; set; }
        public Category Category { get; set; }

        public ICollection<ProductImage> Images { get; set; } = new List<ProductImage>();
    }

    //public class ProductGalleryImages
    //{
    //    [Key]
    //    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    //    public int ID { get; set; }
    //    public int ProductID { get; set; }
    //    [ForeignKey("ProductID")]
    //    public Product Product { get; set; }
    //    public string ImagePath { get; set; } = "";
    //}
    public class ProductImage
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int ID { get; set; }

        public int ProductID { get; set; }
        [ForeignKey("ProductID")]
        public Product Product { get; set; }

        public string ImagePath { get; set; } = "";

        public string FullImagePath(IWebHostEnvironment hostingEnvironment)
        {
            var webRootPath = hostingEnvironment.WebRootPath;
            return Path.Combine(webRootPath, ImagePath);
        }
    }

    public class Order
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public List<OrderItem> OrderItems { get; set; }
    }

    public class OrderItem
    {
        public int Id { get; set; }
        public int ProductId { get; set; }
        public int Quantity { get; set; }
        public decimal Price { get; set; }
        public Product Product { get; set; }
        public Order Order { get; set; }
    }

}
