using System.ComponentModel.DataAnnotations;

namespace Kind_Heart_Charity.Models.Authentication.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage="User Name is Required")]
        public string? Username { get; set; }

        [EmailAddress]
        public string? Email { get; set; }

        [Required(ErrorMessage = "User Password is Required")]
        public string? Password { get; set; }

    }
}
