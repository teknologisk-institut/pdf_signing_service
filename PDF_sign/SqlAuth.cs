using System.ComponentModel.DataAnnotations;

namespace PDF_sign
{
    internal class SqlAuth
    {
        [Key]
        public string? Name { get; set; }
        public string? Password { get; set; }

    }
}
