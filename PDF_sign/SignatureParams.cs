namespace PDF_sign
{
    internal class SignatureParams
    {
        public string? PdfBase64 { get; set; }
        public string? Language { get; set; }
        public string? EmployeeID { get; set; }
        public string? EmployeeFullName { get; set; }
        public string? FileName { get; set; }
        public float? LeftMM { get; set; }
        public float? BottomMM { get; set; }
        public string? AppName { get; set; }
        public string? AppSecret{ get; set; }
    }
}
