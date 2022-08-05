using System.ComponentModel.DataAnnotations;

namespace PDF_sign
{
    internal class SqlLog
    {
        [Key]
        public long? Date { get; set; }
        public string? FileHash { get; set; }
        public string? AppName { get; set; }
        public string? FileName { get; set; }
        public string? EmployeeID { get; set; }
        public string? Language { get; set; }
        public string? EmployeeFullName { get; set; }
        public float? LeftMM { get; set; }
        public float? BottomMM { get; set; }

    }
}
