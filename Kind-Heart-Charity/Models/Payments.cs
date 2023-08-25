using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Kind_Heart_Charity.Models
{
    public class Payments
    {
        public Payments() { }

        public Payments(string username, string package, string amount, int v1, int v2)
        {
            Name = username;
            Package = package;
            Amount = amount;
            IsActive = Convert.ToByte(v1);
            Role = v2;
            CreatedDate = DateTime.Now;
        }

        public int Id { get; set; }
        public string Name { get; set; }
        public string Package { get; set; }
        public string Amount { get; set; }
        public byte IsActive { get; set; }
        public int Role { get; set; }
        public DateTime CreatedDate { get; set; }
    }
}