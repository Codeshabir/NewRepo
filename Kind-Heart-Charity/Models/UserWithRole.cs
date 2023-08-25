namespace Kind_Heart_Charity.Models
{
    public class UserWithRoleDTO
    {
        public string? UserId { get; set; }
        public string? UserName { get; set; }
        public string? Password { get; set; }
        public string? Email { get; set; }
        public DateTime? CreatedDate { get; set; }
        public string? SelectedRole { get; set; }
        public string? Role { get; set; }
        public List<string>? RolesList { get; set; } // Getting Roles List

    }
}
