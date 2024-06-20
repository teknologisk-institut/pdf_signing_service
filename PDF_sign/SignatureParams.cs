namespace PDF_sign
{
    internal class SignatureParams
    {
        public string? PdfBase64 { get; set; }
        public string? Language { get; set; }
        public string? EmployeeID { get; set; }
        public string? EmployeeFullName { get; set; }
        public string? FileName { get; set; }
        public string? AppName { get; set; }
        public string? AppSecret { get; set; }
        public string? Reason { get; set; }
        public string? Location { get; set; }
        public string? Contact { get; set; }
        public bool? NoVisualSignature { get; set; }
        public int? SignaturePageIndex { get; set; }
        public string? SignatureImageBase64 { get; set; }
        public int? SignatureDatePositionX { get; set; }
        public float? SignatureDatePositionY { get; set; }
        public float? SignatureDateFontSize { get; set; }
        public float? SignatureLeftMM { get; set; }
        public float? SignatureBottomMM { get; set; }
        public float? SignatureWidthMM { get; set; }
        public float? SignatureHeightMM { get; set; }
        public bool? IsDancert { get; set; }
        public string? Org { get; set; }
    }
}
