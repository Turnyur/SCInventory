using Microsoft.AspNetCore.Identity;

namespace SCInventory.Models
{
    public class Member: IdentityUser
    {
        public int firstname { get; set; }
        public int lastname { get; set; }
    }
}
