using MessagePack;
using System.ComponentModel.DataAnnotations;

namespace Kind_Heart_Charity.Models.Mailing
{
    public class MailingList
    {
        
        public int Id { get; set; }
        public string Email { get; set; }
        public DateTime CreatedDate { get; set;}
    }
}
