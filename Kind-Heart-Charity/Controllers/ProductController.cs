using Kind_Heart_Charity.Data;
using Kind_Heart_Charity.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Http;
using System.Text;


namespace Kind_Heart_Charity.Controllers
{
    public class ProductController : Controller
    {
        private readonly Kind_Heart_CharityContext _context;
        private readonly IWebHostEnvironment _hostingEnvironment;


        public ProductController(Kind_Heart_CharityContext context, IWebHostEnvironment hostingEnvironment)
        {
            _context = context;
            _hostingEnvironment = hostingEnvironment;
        }



        //[HttpGet]
        //public IActionResult Index()
        //{
        //    var categories = _context.Categories.Include(c => c.Products).ToList();
        //    var products = categories.SelectMany(c => c.Products).ToList();

        //    return View(products);
        //}



        //[HttpGet]
        //public IActionResult Index(int? categoryId)
        //{
        //    var categories = _context.Categories.ToList();
        //    var products = _context.Products.ToList();

        //    if (categoryId.HasValue)
        //    {
        //        products = products.Where(p => p.CategoryId == categoryId.Value).ToList();
        //    }

        //    ViewBag.AllCategories = categories;

        //    return View(products);
        //}

        [HttpGet]
        public IActionResult Index(int? categoryId)
        {
            var categories = _context.Categories.ToList();
            var products = _context.Products.ToList();

            if (categoryId.HasValue)
            {
                products = products.Where(p => p.CategoryId == categoryId.Value).ToList();
            }

            // Create a list of ProductViewModel
            var productViewModels = new List<ProductViewModel>();

            foreach (var product in products)
            {
                var productViewModel = new ProductViewModel
                {
                    Id = product.Id,
                    Name = product.Name,
                    Price = product.Price,
                    Description = product.Description,
                    CategoryId = product.CategoryId,
                    Categories = categories,
                    Images = _context.ProductImage.Where(pi => pi.ProductID == product.Id).ToList() // Populate the Images property with the corresponding product images
                };

                productViewModels.Add(productViewModel);
            }

            ViewBag.AllCategories = categories;

            return View(productViewModels);
        }

        [HttpGet]
        public IActionResult ProductDetail(int id)
        {
            var product = _context.Products.Include(p => p.Images).FirstOrDefault(p => p.Id == id);

            if (product == null)
            {
                return NotFound();
            }

            var productViewModel = new ProductViewModel
            {
                Id = product.Id,
                Name = product.Name,
                Price = product.Price,
                Description = product.Description,
                Images = product.Images.ToList() // Ensure that the Images property is populated
            };

            return View(productViewModel);
        }





        [HttpGet]
            public IActionResult AddCategory()
            {
                return View();
            }


        public JsonResult GetCategories(int LastRowId = 0, int PageSize = 25, string query = "", int Direction = 0)
        {
            int tempLastRowId = LastRowId;
            if (Direction < 0)
                tempLastRowId = LastRowId - PageSize;
            else if (Direction > 0)
                tempLastRowId = LastRowId + PageSize;
            else
                tempLastRowId = LastRowId;

            if (tempLastRowId < 0)
                tempLastRowId = 0;
            List<CategoryViewModel> data = new List<CategoryViewModel>();
            _context.Categories.ToList().ForEach(x => data.Add(new CategoryViewModel() { Id = x.Id, Name = x.Name }));
            if (!string.IsNullOrEmpty(query))
            {
                data.Where(x => x.Name.Contains(query) );
            }
            if (data.Count > 0)
            {
                return Json(new { response = data, Status = true, LastRowID = tempLastRowId, PageSize = PageSize,  Count = data.Count });
            }
            else
            {
                return Json(new { response = data, Status = false, LastRowID = tempLastRowId, PageSize = PageSize, TotalRecord = data.Count, Count = data.Count });
            }
        }




        [HttpPost]
            public IActionResult AddCategory(CategoryViewModel categoryViewModel)
            {
                var category = new Category
                {
                    Name = categoryViewModel.Name
                };

                _context.Categories.Add(category);
                _context.SaveChanges();

            return Json(new { response = "Category added successfully.", Status = true });
        }

        [HttpGet]
            public IActionResult EditCategory(int id)
            {
                var category = _context.Categories.Find(id);
                var viewModel = new CategoryViewModel
                {
                    Id = category.Id,
                    Name = category.Name,
                    Products = category.Products
                };

                return View(viewModel);
            }

            [HttpPost]
            public IActionResult EditCategory(CategoryViewModel categoryViewModel)
            {
                var category = _context.Categories.Find(categoryViewModel.Id);
                category.Name = categoryViewModel.Name;

                _context.SaveChanges();

                return RedirectToAction("Index");
            }

            [HttpPost]
            public IActionResult DeleteCategory(int id)
            {
                var category = _context.Categories.Find(id);
                _context.Categories.Remove(category);
                _context.SaveChanges();

                return RedirectToAction("Index");
            }

            [HttpGet]
            public IActionResult AddProduct()
        {
            var categories = _context.Categories.ToList();
            var viewModel = categories.Select(category => new CategoryViewModel
            {
                Id = category.Id,
                Name = category.Name,
                Products = category.Products
            }).ToList();

            return View(viewModel);
        }


        //    [HttpPost]
        //    public IActionResult AddProduct(ProductViewModel productViewModel)
        //    {
        //        var product = new Product
        //        {
        //            Name = productViewModel.Name,
        //            Price = productViewModel.Price,
        //            Description = productViewModel.Description,
        //            CategoryId = productViewModel.CategoryId
        //        };

        //        _context.Products.Add(product);
        //        _context.SaveChanges();

        //    return Json(new { response = "Product added successfully.", Status = true});
        //}



        [HttpPost]
        public IActionResult AddProduct(ProductViewModel productViewModel)
        {
            var productEntity = new Product
            {
                Name = productViewModel.Name,
                Price = productViewModel.Price,
                Description = productViewModel.Description,
                CategoryId = productViewModel.CategoryId,
                // Set any other relevant properties
            };

            if (productViewModel.ImageFile != null && productViewModel.ImageFile.Length > 0)
            {
                var fileName = $"{productEntity.Id}_{productViewModel.ImageFile.FileName}";
                var imagePath = Path.Combine("images", "product_images", fileName);

                var productImage = new ProductImage
                {
                    ImagePath = "\\" + imagePath.Replace("\\", "/") // Add a backslash before the path and replace slashes
                };

                productEntity.Images.Add(productImage);

                var filePath = Path.Combine(_hostingEnvironment.WebRootPath, imagePath);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    productViewModel.ImageFile.CopyTo(stream);
                }
            }

            _context.Products.Add(productEntity);
            _context.SaveChanges();

            return Json(new { response = "Product added successfully.", status = true });
        }

        [HttpGet]
            public IActionResult EditProduct(int id)
            {
                var product = _context.Products.Find(id);
                var categories = _context.Categories.ToList();
                var viewModel = new ProductViewModel
                {
                    Id = product.Id,
                    Name = product.Name,
                    Price = product.Price,
                    Description = product.Description,
                    CategoryId = product.CategoryId,
                    Categories = categories
                };

                return View(viewModel);
            }

            [HttpPost]
            public IActionResult EditProduct(ProductViewModel productViewModel)
            {
                var product = _context.Products.Find(productViewModel.Id);
                product.Name = productViewModel.Name;
                product.Price = productViewModel.Price;
                product.Description = productViewModel.Description;
                product.CategoryId = productViewModel.CategoryId;

                _context.SaveChanges();

                return RedirectToAction("Index");
            }
            public JsonResult GetProducts(int LastRowId = 0, int PageSize = 25, string query = "", int Direction = 0)
        {
            int tempLastRowId = LastRowId;
            if (Direction < 0)
                tempLastRowId = LastRowId - PageSize;
            else if (Direction > 0)
                tempLastRowId = LastRowId + PageSize;
            else
                tempLastRowId = LastRowId;

            if (tempLastRowId < 0)
                tempLastRowId = 0;
            List<ProductViewModel> data = new List<ProductViewModel>();
            _context.Products.ToList().ForEach(x => data.Add(new ProductViewModel() { Id = x.Id, Name = x.Name, Price = x.Price, Description = x.Description, CategoryId = x.CategoryId }));
            if (!string.IsNullOrEmpty(query))
            {
                data.Where(x => x.Name.Contains(query));
            }
            if (data.Count > 0)
            {
                return Json(new { response = data, Status = true, LastRowID = tempLastRowId, PageSize = PageSize, Count = data.Count });
            }
            else
            {
                return Json(new { response = data, Status = false, LastRowID = tempLastRowId, PageSize = PageSize, TotalRecord = data.Count, Count = data.Count });
            }
        }

            [HttpPost]
            public IActionResult DeleteProduct(int id)
            {
                var product = _context.Products.Find(id);
                _context.Products.Remove(product);
                _context.SaveChanges();

                return RedirectToAction("Index");
            }


        // Cart 

        //[HttpGet]
        //public IActionResult AddToCart(int productId, int quantity, decimal price)
        //{
        //    // Logic to add the product to the cart and update the session or database accordingly
        //    // You can access the current user's cart using the session or database, and add the product with the specified quantity and price

        //    // Example code to update the session-based cart
        //    var cartJson = HttpContext.Session.GetString("Cart");
        //    var cart = string.IsNullOrEmpty(cartJson) ? new List<CartItem>() : JsonConvert.DeserializeObject<List<CartItem>>(cartJson);

        //    var existingItem = cart.FirstOrDefault(item => item.productId == productId);
        //    if (existingItem != null)
        //    {
        //        // If the product already exists in the cart, update its quantity
        //        existingItem.quantity += quantity;
        //    }
        //    else
        //    {
        //        // If the product doesn't exist in the cart, create a new cart item
        //        var newItem = new CartItem
        //        {
        //            productId = productId,
        //            quantity = quantity,
        //            pricePerUnit = price
        //        };
        //        cart.Add(newItem);
        //    }

        //    var updatedCartJson = JsonConvert.SerializeObject(cart);
        //    HttpContext.Session.SetString("Cart", updatedCartJson);

        //    // Prepare the response data
        //    var responseData = new
        //    {
        //        status = true,
        //        message = "Product added to cart successfully",
        //        shoppinglist = cart
        //    };

        //    return Json(responseData);
        //}




        public IActionResult AddToCart(int productId, int quantity, decimal price)
        {
            var cart = GetCartFromSession();

            var existingItem = cart.FirstOrDefault(item => item.productId == productId);
            if (existingItem != null)
            {
                // If the product already exists in the cart, update its quantity
                existingItem.quantity += quantity;
            }
            else
            {
                // If the product doesn't exist in the cart, create a new cart item
                var newItem = new CartItem
                {
                    productId = productId,
                    productTitle = "Product Title", // Provide the actual product title
                    quantity = quantity,
                    pricePerUnit = price
                };
                cart.Add(newItem);
            }

            SaveCartToSession(cart);

            var responseData = new
            {
                status = true,
                message = "Product added to cart successfully",
                shoppinglist = cart
            };

            return Json(responseData);
        }

        public IActionResult CheckoutOrder()
        {
            var cart = GetCartFromSession();

            if (cart == null || cart.Count == 0)
            {
                return RedirectToAction("CartIsEmpty", "Product");
            }

            ClearCartFromSession();

            var responseData = new
            {
                status = true,
                redirectUrl = Url.Action("CartItems", "Product"),
                shoppinglist = cart
            };

            return Json(responseData);
        }

        public IActionResult CartItems()
        {
            var cartItems = GetCartFromSession();

            return View(cartItems);
        }


        private List<CartItem> GetCartFromSession()
        {
            var cartJson = HttpContext.Session.GetString("Cart");
            var cart = !string.IsNullOrEmpty(cartJson) ? JsonConvert.DeserializeObject<List<CartItem>>(cartJson) : new List<CartItem>();
            return cart;
        }



        private void SaveCartToSession(List<CartItem> cart)
    {
        var cartJson = JsonConvert.SerializeObject(cart);
        var cartBytes = Encoding.UTF8.GetBytes(cartJson);
        HttpContext.Session.Set("Cart", cartBytes);
    }


    private void ClearCartFromSession()
        {
            HttpContext.Session.Remove("Cart");
        }







     






        //public IActionResult AddToCart(int productId, int quantity, decimal price)
        //{
        //    // Logic to add the product to the cart and update the session or database accordingly
        //    // You can access the current user's cart using the session or database, and add the product with the specified quantity and price

        //    // Example code to update the session-based cart
        //    var cartJson = HttpContext.Session.GetString("Cart");
        //    var cart = string.IsNullOrEmpty(cartJson) ? new List<CartItem>() : JsonConvert.DeserializeObject<List<CartItem>>(cartJson);

        //    var existingItem = cart.FirstOrDefault(item => item.productId == productId);
        //    if (existingItem != null)
        //    {
        //        // If the product already exists in the cart, update its quantity
        //        existingItem.quantity += quantity;
        //    }
        //    else
        //    {
        //        // If the product doesn't exist in the cart, create a new cart item
        //        var newItem = new CartItem
        //        {
        //            productId = productId,
        //            quantity = quantity,
        //            pricePerUnit = price
        //        };
        //        cart.Add(newItem);
        //    }

        //    var updatedCartJson = JsonConvert.SerializeObject(cart);
        //    HttpContext.Session.SetString("Cart", updatedCartJson);

        //    // Prepare the response data
        //    var responseData = new
        //    {
        //        status = true,
        //        message = "Product added to cart successfully",
        //        shoppinglist = cart
        //    };

        //    return Json(responseData);
        //}


        //[HttpGet]
        //public IActionResult CheckoutOrder()
        //{
        //    // Logic to process the order and place it
        //    // You can access the current user's cart using the session or database and perform the necessary operations to place the order

        //    // Example code to retrieve the cart items before clearing the cart
        //    var cartJson = HttpContext.Session.GetString("Cart");
        //    var cart = string.IsNullOrEmpty(cartJson) ? new List<CartItem>() : JsonConvert.DeserializeObject<List<CartItem>>(cartJson);

        //    // Clear the session-based cart after placing the order
        //    HttpContext.Session.Remove("Cart");

        //    // Convert the cart items to a new list with uppercase property names


        //    // Prepare the response data with the redirect URL and the updated cart items
        //    var responseData = new
        //    {
        //        status = true,
        //        redirectUrl = Url.Action("CartItems", "Product"),
        //        shoppinglist = cart
        //    };

        //    return Json(responseData);
        //}

        //[HttpGet]
        //public IActionResult CartItems()
        //{
        //    // Retrieve the cart items from the session or database
        //    var cartJson = HttpContext.Session.GetString("Cart");
        //    var cartItems = string.IsNullOrEmpty(cartJson) ? new List<CartItem>() : JsonConvert.DeserializeObject<List<CartItem>>(cartJson);

        //    // Pass the cart items to the view
        //    return View(cartItems);
        //}


    }





}
