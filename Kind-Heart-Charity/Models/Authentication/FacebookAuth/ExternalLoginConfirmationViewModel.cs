using System.ComponentModel.DataAnnotations;

namespace Kind_Heart_Charity.Models.Authentication.FacebookAuth
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        // Add any additional properties you need for the registration process
    }

    public class ExternalLoginViewModel
    {
        public string ReturnUrl { get; set; }
        public string LoginProvider { get; set; }
    }

}
