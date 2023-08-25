using Kind_Heart_Charity.Data;
using Kind_Heart_Charity.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Drawing.Printing;
using System.IO;

namespace Kind_Heart_Charity.Controllers
{
    public class DynamicPagesController : Controller
    {
        private readonly Kind_Heart_CharityContext _context;
        private readonly IWebHostEnvironment _hostingEnvironment;
        public DynamicPagesController(Kind_Heart_CharityContext context, IWebHostEnvironment hostingEnvironment)
        {
            _context = context;
            _hostingEnvironment = hostingEnvironment;
        }
        public async Task<IActionResult> DynamicPages()
        {
            await GetViewBagData();
            //if (User.Identity.Name == null)
            //{
            //    return Redirect("/Authentication/Signin");
            //}
            //else
            //{
            return View();
            //}
        }

        public async Task<IActionResult> Index()
        {
           
            return View();
           
        }

        public JsonResult GetDynamicPages(int LastRowId = 0, int PageSize = 25, string query = "", int Direction = 0)
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
            List<DynamicPagesDBDTO> data = new List<DynamicPagesDBDTO>();
            _context.DynamicPages.Where(x=>x.IsDeleted==false).ToList().ForEach(x => data.Add(new DynamicPagesDBDTO() { Id = x.Id, PageName = x.PageName, TotalRecords = 0, SectionName = x.SectionName }));
            if(!string.IsNullOrEmpty(query))
            {
                data.Where(x => x.SectionName.Contains(query) || x.PageTitle.Contains(query));
            }
            if (data.Count > 0)
            {
                return Json(new { response = data, Status = true, LastRowID = tempLastRowId, PageSize = PageSize, TotalRecord = data.FirstOrDefault().TotalRecords, Count = data.Count });
            }
            else
            {
                return Json(new { response = data, Status = false, LastRowID = tempLastRowId, PageSize = PageSize, TotalRecord = data.Count, Count = data.Count });
            }
        }

        [HttpGet]
        public JsonResult GetPagePost(int LastRowId = 0, int PageSize = 25, string query = "", int Direction = 0)
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
            List<PagePostDBDTO> data = new List<PagePostDBDTO>();
            int pageID = (int)TempData["PageID"];
            TempData.Keep();
            _context.PagePosts.Where(x=>x.DynamicPageID==pageID && x.IsDeleted==false).ToList().ForEach(x => data.Add(new PagePostDBDTO() { ID = x.ID, PostTitle = x.PostTitle, TotalRecords = 0, PostThumbnail = x.PostThumbnail }));
            if (data.Count > 0)
            {
                return Json(new { response = data, Status = true, LastRowID = tempLastRowId, PageSize = PageSize, TotalRecord = data.FirstOrDefault().TotalRecords, Count = data.Count });
            }
            else
            {
                return Json(new { response = data, Status = false, LastRowID = tempLastRowId, PageSize = PageSize, TotalRecord = data.Count, Count = data.Count });
            }
        }

        [HttpGet]
        public async Task<JsonResult> DeleteDynamicPage(int id)
        {
            var data=await _context.DynamicPages.Where(x=>x.Id==id).FirstOrDefaultAsync();
            data.IsDeleted = true;
            await _context.SaveChangesAsync();
            return Json(new { response = "Page removed successfully.", Status = true });
        }


        [HttpPost]
        public async Task<IActionResult> CreateDynamicPages(DynamicPagesDTO dynamicPagesDTO)
        {
            if (_context.DynamicPages.Where(x => x.PageName.Equals(dynamicPagesDTO.PageName)).Count() == 0)
            {
                var dynamicPages = new DynamicPages()
                {
                    PageName = dynamicPagesDTO.PageName,
                    SectionName = dynamicPagesDTO.SectionName,
                };
                await _context.DynamicPages.AddAsync(dynamicPages);
                await _context.SaveChangesAsync();
                return Json(new { response = "Page added successfully.", Status = true });
            }
            return Json(new { response = "Page already added.", Status = false });
        }

        [HttpGet]
        public async Task<IActionResult> AddPost(int pageID)
        {
            List<DynamicPagesDBDTO> data = new List<DynamicPagesDBDTO>();
            _context.DynamicPages.Where(x=>x.IsDeleted==false).ToList().ForEach(x => data.Add(new DynamicPagesDBDTO() { Id = x.Id, PageName = x.PageName, SectionName = x.SectionName }));
            ViewBag.DynamicPages = data;
            TempData["PageID"] = pageID;
            //List<DynamicPagesDBDTO> data = new List<DynamicPagesDBDTO>();
            var dynamicPage = _context.DynamicPages.Where(x=>x.IsDeleted==false).Where(x => x.Id == pageID).FirstOrDefault();

            return View(dynamicPage);
        }

        [HttpPost]
        public async Task<IActionResult> CreatePost(PagePostWebDTO pagePostWeb)
        {
            if (pagePostWeb != null && !string.IsNullOrEmpty(pagePostWeb.PostTitle) && !string.IsNullOrEmpty(pagePostWeb.PostDescription))
            {
                string uriPath = "/Icons/Games/";
                string path = _hostingEnvironment.WebRootPath + uriPath;
                IFormFile fileUpload = default;
                string filePath = "";
                if (Request.Form.Files.Count > 0)
                {
                    List<string> filesName = new List<string>();
                    foreach (var item in Request.Form.Files)
                    {
                        fileUpload = item;
                        if (!Directory.Exists(path))
                        {
                            Directory.CreateDirectory(path);
                        }
                        var fileName = Path.GetFileName(fileUpload.FileName);
                        fileName = fileName.Replace("'", "");
                        fileName = fileName.Replace(" ", "");
                        string fullFileName = DateTime.Now.ToString("yyyyMMddHHmmssfff") + "_" + fileName;
                        filePath = path + fullFileName;
                        filesName.Add(fullFileName);
                        using (var fileStream = new FileStream(filePath, FileMode.Create))
                        {
                            fileUpload.CopyTo(fileStream);
                        }
                    }

                    var pagePosts = new PagePost()
                    {
                        DynamicPageID = pagePostWeb.DynamicPageID,
                        PostDescription = pagePostWeb.PostDescription,
                        PostThumbnail = uriPath + filesName[0],
                        PostTitle = pagePostWeb.PostTitle
                    };
                    await _context.PagePosts.AddAsync(pagePosts);
                    await _context.SaveChangesAsync();
                    List<PostGalleryImages> postGalleryImages = new List<PostGalleryImages>();
                    filesName.ForEach(x => postGalleryImages.Add(new PostGalleryImages() { ImagePath = uriPath + x, PostID = pagePosts.ID }));
                    await _context.PostGalleryImages.AddRangeAsync(postGalleryImages);
                    await _context.SaveChangesAsync();
                    return Json(new { response = "Post Added Successfully", Status = true, });

                }
                return Json(new { response = "Please enter the required fields", Status = false, });


            }
            else
            {
                return Json(new { message = "Server 404 Err", Status = false, });

            }

            //fileUpload.(filePath);


        }
        private async Task GetViewBagData()
        {
            List<DynamicPagesDBDTO> data = new List<DynamicPagesDBDTO>();
            _context.DynamicPages.Where(x => x.IsDeleted == false).ToList().ForEach(x => data.Add(new DynamicPagesDBDTO() { Id = x.Id, PageName = x.PageName, SectionName = x.SectionName }));
            ViewBag.DynamicPages = data;
        }


        [HttpGet]
        public async Task<JsonResult> DeletePagePost(int id)
        {
            var data = await _context.PagePosts.Where(x => x.ID == id).FirstOrDefaultAsync();
            data.IsDeleted = true;
            await _context.SaveChangesAsync();
            return Json(new { response = "Page removed successfully.", Status = true });
        }

    }
}
