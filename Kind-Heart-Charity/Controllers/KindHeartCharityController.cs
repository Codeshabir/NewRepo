using Kind_Heart_Charity.Data;
using Kind_Heart_Charity.Models;
using Microsoft.AspNetCore.Mvc;

namespace Kind_Heart_Charity.Controllers
{
    public class KindHeartCharityController : Controller
    {
        private readonly Kind_Heart_CharityContext _context;
        private readonly IWebHostEnvironment _hostingEnvironment;


        public KindHeartCharityController(Kind_Heart_CharityContext context, IWebHostEnvironment hostingEnvironment)
        {
            _context = context;
            _hostingEnvironment = hostingEnvironment;

        }




        public async Task<IActionResult> Index(int pageID)
        {
            await GetViewBags();
            var resPosts=_context.PagePosts.Where(x => x.DynamicPageID == pageID).ToList();
            return View(resPosts);
        }

        //public ActionResult UploadImage(List<IFormFile> files)
        //{
        //    var filepath = "";
        //    foreach (IFormFile photo in Request.Form.Files)
        //    {
        //        string serverMapPath = Path.Combine(_hostingEnvironment.WebRootPath, "images", photo.FileName);
        //        using (var stream = new FileStream(serverMapPath, FileMode.Create))
        //        {
        //            photo.CopyTo(stream);
        //        }
        //        filepath = "http://localhost:8080/KindHeartCharity/Index?pageID=50/" + "images/" + photo.FileName;
        //        // Add a forward slash between pageID=50 and images/ in the filepath
        //    }
        //    return Json(new { url = filepath });
        //}

        public ActionResult UploadImage(List<IFormFile> files)
        {
            var baseUrl = "http://localhost:8080/KindHeartCharity/Index";
            var imageUrls = new List<string>();

            foreach (IFormFile photo in Request.Form.Files)
            {
                string uniqueFileName = Guid.NewGuid().ToString() + "_" + photo.FileName;
                string serverMapPath = Path.Combine(_hostingEnvironment.WebRootPath, "images", uniqueFileName);

                using (var stream = new FileStream(serverMapPath, FileMode.Create))
                {
                    photo.CopyTo(stream);
                }

                // Construct the relative URL for the image
                string relativePath = "/images/" + uniqueFileName;

                // Construct the full image URL
                string imageUrl = new Uri(new Uri(baseUrl), relativePath).ToString();

                // Add the full image URL to the list of image URLs
                imageUrls.Add(imageUrl);
            }

            return Json(new { urls = imageUrls });
        }




        //[HttpPost("Upload")]
        //public async Task<IActionResult> UploadImage(IFormFile file)
        //{
        //    try
        //    {
        //        if (file == null || file.Length == 0)
        //        {
        //            return BadRequest("No file selected for upload.");
        //        }

        //        // Generate a unique filename to avoid conflicts
        //        string uniqueFileName = Guid.NewGuid().ToString() + "_" + file.FileName;

        //        // Get the path where images will be stored
        //        string uploadPath = Path.Combine(_hostingEnvironment.WebRootPath, "uploads");

        //        // Ensure the uploads directory exists; create it if not
        //        if (!Directory.Exists(uploadPath))
        //        {
        //            Directory.CreateDirectory(uploadPath);
        //        }

        //        // Combine the upload path with the unique filename
        //        string filePath = Path.Combine(uploadPath, uniqueFileName);

        //        // Save the file to the server
        //        using (var fileStream = new FileStream(filePath, FileMode.Create))
        //        {
        //            await file.CopyToAsync(fileStream);
        //        }

        //        // Return the URL of the uploaded image
        //        string imageUrl = Url.Content("~/uploads/" + uniqueFileName);

        //        return Ok(new { imageUrl });
        //    }
        //    catch (Exception ex)
        //    {
        //        return StatusCode(500, $"An error occurred while uploading the image: {ex.Message}");
        //    }
        //}


        public async Task<IActionResult> PostDetails(int postID)
        {
            await GetViewBags();
            var resPosts = _context.PagePosts.Where(x => x.ID == postID).FirstOrDefault();
            var resPostImages = new List<PostGalleryImages>();
            if(resPosts!=null)
            {
                resPostImages=_context.PostGalleryImages.Where(x => x.PostID == postID).ToList();
            }
            return View((resPosts,resPostImages));
        }
        private async Task GetViewBags()
        {
            List<DynamicPagesDBDTO> data = new List<DynamicPagesDBDTO>();
            _context.DynamicPages.ToList().ForEach(x => data.Add(new DynamicPagesDBDTO() { Id = x.Id, PageName = x.PageName, TotalRecords = 0, SectionName = x.SectionName }));
            ViewBag.AllPages = data;
            var SectionName = data.GroupBy(x => x.SectionName).Select(x => x.Key);
            ViewBag.SectionName = SectionName;
        }
    }
}
