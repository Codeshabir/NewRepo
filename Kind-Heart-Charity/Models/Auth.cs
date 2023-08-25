using System;
namespace Kind_Heart_Charity.Models
{
	public class Auth
	{
		public Auth()
		{
		}

        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public byte IsActive { get; set; }
        public int Role { get; set; }
    }
}

