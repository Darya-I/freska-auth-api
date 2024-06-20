using System.ComponentModel.DataAnnotations;

namespace Auth_API.Models.DTOs
{
    public class UserRegistrationDTO
    {
        [Required]
        public string Name { get; set; }
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
