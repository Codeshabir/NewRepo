using System.ComponentModel.DataAnnotations;

namespace Kind_Heart_Charity.Models.Authentication.Login
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Email is Required")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Password is Required")]
        public string? Password { get; set; }
    }
}
