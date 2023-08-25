namespace Kind_Heart_Charity.Models
{
    public class CategoryViewModel
    {
        public int Id { get; set; } 
        public string Name { get; set; }
        public List<Product> Products { get; set; }
        public int MyProperty { get; set; }
    }

    public class ProductViewModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public decimal Price { get; set; }
        public string Description { get; set; }
        public int CategoryId { get; set; }
        public List<Category> Categories { get; set; }
        public IFormFile ImageFile { get; set; } // Property for the image file
        public List<ProductImage> Images { get; set; } = new List<ProductImage>(); // Property for product images
    }

    public class OrderViewModel
    {
        public List<OrderItem> OrderItems { get; set; }
        public decimal TotalPrice => OrderItems.Sum(item => item.Quantity * item.Price);
    }
    public class CartItem
    {
        public int productId { get; set; }
        public string productTitle { get; set; }
        public int quantity { get; set; }
        public decimal pricePerUnit { get; set; }
        public decimal productPrice => quantity * pricePerUnit;
    }

}
