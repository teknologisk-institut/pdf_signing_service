using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PDF_sign
{
    internal class SignatureParams
    {
        public string pdfBase64 { get; set; }
        public string reason { get; set; }
        public string location { get; set; }
        public string contact { get; set; }
        public string language { get; set; }
        public string signatureCreator { get; set; }
    }
}
