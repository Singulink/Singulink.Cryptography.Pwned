using System.ComponentModel.DataAnnotations;

namespace Singulink.Cryptography.Pwned.Service.Models;

public class Password
{
    [Key]
    public string Hash { get; set; } = string.Empty;

    [Required]
    public int Count { get; set; }
}
