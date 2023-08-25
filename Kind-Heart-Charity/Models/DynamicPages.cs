using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Kind_Heart_Charity.Models
{

    public class DynamicPagesDBDTO
    {
        public int Id { get; set; }
        public string PageName { get; set; } = "";
        public string PageTitle { get; set; } = "";
        public string SectionName { get; set; } = "";
        public int TotalRecords { get; set; }
    }
    public class DynamicPagesDTO
    {
        public string PageName { get; set; } = "";
        public string PageTitle { get; set; } = "";
        public string SectionName { get; set; } = "";
        IList<IFormFile> files { get; set; }

    }


    public class DynamicPages
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string PageName { get; set; } = "";
        public string SectionName { get; set; } = "";
        public bool IsDeleted { get; set; } = false;
    }
    public class PagePost
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int ID { get; set; }
        public int DynamicPageID { get; set; }

        [ForeignKey("DynamicPageID")]
        public DynamicPages DynamicPages { get; set; }
        public string PostTitle { get; set; } = String.Empty;
        public string PostDescription { get; set; } = String.Empty;
        public string PostThumbnail { get; set; } = String.Empty;
        public bool IsDeleted { get; set; } = false;
        

    }
    public class PostGalleryImages
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int ID { get; set; }
        public int PostID { get; set; }
        [ForeignKey("PostID")]
        public PagePost PagePost { get; set; }
        public string ImagePath { get; set; } = "";
    }
       

    public class PagePostWebDTO
    {
        public int DynamicPageID { get; set; }
        public string PostTitle { get; set; } = string.Empty;
        public string PostDescription { get; set; } = string.Empty;
    }


    public class PagePostDBDTO
    {
        public int ID { get; set; }
        public string PostTitle { get; set; } = string.Empty;
        public string PostThumbnail { get; set; } = string.Empty;
        public int TotalRecords { get; set; } 
    }
}
