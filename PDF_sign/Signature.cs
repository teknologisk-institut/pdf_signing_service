
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.IO.Image;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using System.Drawing;
using System.Globalization;
using System.Drawing.Text;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;

namespace PDF_sign
{
    public class Signature
    {
        private static ExternalSignature? tiSignature;
        private static Org.BouncyCastle.X509.X509Certificate[]? tiChain;

        private static ExternalSignature? danSignature;
        private static Org.BouncyCastle.X509.X509Certificate[]? danChain;

        private static readonly SHA256 sha = SHA256.Create();

        private static readonly bool debug = false;

        public static void SetupSignature()
        {
            SetupCertChains();
            tiSignature = new ExternalSignature(0);
            danSignature = new ExternalSignature(1);
        }

        public static string Sign(string json)
        {
            try
            {
                using var db = new SqlContext();

                if (debug) Console.WriteLine("Signing started");

                if (debug) Console.WriteLine("Certificate loaded");

                if (db.Auth == null) throw new Exception("Auth database not found");

                var pass = db.Auth.Find("certificate");
                if (pass == null || pass.Password == null) throw new Exception("Certificate password not found");

                var pars = JsonConvert.DeserializeObject<SignatureParams>(json);

                if (pars == null) throw new Exception("Wrong parameters: " + json);

                if (pars.Language == null) pars.Language = "en";

                if (pars.Language != "en" && pars.Language != "da" && pars.Language != "de")
                {
                    throw new Exception("Unsupported language: " + pars.Language);
                }

                if (pars.PdfBase64 == null) throw new Exception("Missing property: pdfBase64");

                if (pars.AppName == null) throw new Exception("Missing property: appName");

                if (pars.AppSecret == null) throw new Exception("Missing property: appSecret");

                if (pars.EmployeeID == null) throw new Exception("Missing property: employeeID");

                if (pars.EmployeeFullName == null) throw new Exception("Missing property: employeeFullName");

                var app = db.Auth.Find(pars.AppName);
                if (app == null) throw new Exception("AppName not found: " + pars.AppName);

                if (pars.AppSecret != app.Password) throw new Exception("Invalid AppSecret: " + pars.AppSecret);

                if (debug) Console.WriteLine("JSON validation performed");

                var arr = PerformSigning(pars);

                db.Add(new SqlLog
                {
                    Date = DateTime.UtcNow,
                    FileHash = Convert.ToBase64String(sha.ComputeHash(arr)),
                    AppName = pars.AppName,
                    EmployeeID = pars.EmployeeID,
                    EmployeeFullName = pars.EmployeeFullName,
                    FileName = pars.FileName,
                    Language = pars.Language,
                });

                db.SaveChanges();

                if (debug) Console.WriteLine("File returned");

                var ob = new JObject() { ["pdfBase64"] = Convert.ToBase64String(arr) };

                return ob.ToString(Formatting.None);
            }
            catch (Exception ex)
            {
                tiSignature = null;
                tiChain = null;
                danSignature = null;
                danChain = null;

                var ob = new JObject() { ["error"] = ex.ToString() };

                return ob.ToString(Formatting.None);
            }
        }

        internal static byte[] PerformSigning(SignatureParams pars)
        {
            if (tiSignature == null || tiChain == null || danSignature == null || danChain == null)
            {
                SetupSignature();
            }

            var pdf = Convert.FromBase64String(pars.PdfBase64!);
            using var inputStream = new MemoryStream(pdf);
            using var reader = new PdfReader(inputStream);

            var props = new StampingProperties();

            using var outputStream = new MemoryStream();
            var signer = new PdfSigner(reader, outputStream, props);

            var appearance = signer.GetSignatureAppearance();

            var reason = pars.Reason != null ? (string)pars.Reason : GetReason(pars.EmployeeFullName!, pars.Language!, pars.IsDancert);
            appearance.SetReason(reason);

            var location = pars.Location != null ? (string)pars.Location : "Gregersensvej 1, 2630 Taastrup, Denmark";
            appearance.SetLocation(location);

            var contact = pars.Contact != null ?
                (string)pars.Contact :
                pars.IsDancert == true ?
                "Phone: +4572202160, E-mail: info@dancert.dk" :
                "Phone: +4572202000, E-mail: info@teknologisk.dk";

            appearance.SetContact(contact);

            appearance.SetSignatureCreator(pars.AppName + " (" + pars.EmployeeID + ")");

            if (pars.NoVisualSignature != true) SetVisualSignature(appearance, pars, signer);

            var tsa = new TSAClientBouncyCastle("http://timestamp.digicert.com", "", "");

            var ocspVerifier = new OCSPVerifier(null, null);
            var ocspClient = new OcspClientBouncyCastle(ocspVerifier);
            var crlClients = new List<ICrlClient>(new[] { new CrlClientOnline() });

            if (pars.IsDancert == true)
            {
                signer.SignDetached(danSignature, danChain, crlClients, ocspClient, tsa, 0, PdfSigner.CryptoStandard.CMS);
            }
            else
            {
                signer.SignDetached(tiSignature, tiChain, crlClients, ocspClient, tsa, 0, PdfSigner.CryptoStandard.CMS);
            }


            if (debug) Console.WriteLine("File signed");

            return outputStream.ToArray();
        }

        private static void SetVisualSignature(PdfSignatureAppearance appearance, SignatureParams pars, PdfSigner signer)
        {
            appearance.SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

            var pageIndex = pars.SignaturePageIndex != null ? (int)pars.SignaturePageIndex : 0;

            if (pageIndex < 0)
            {
                var pageCount = signer.GetDocument().GetNumberOfPages();
                pageIndex += pageCount;
            }

            appearance.SetPageNumber(pageIndex + 1);

            SetPageRect(signer, pars, appearance);

            if (debug) Console.WriteLine("Signature info created");

            using var image = GetSignatureImage(pars);
            using var graphics = Graphics.FromImage((Bitmap)image);
            graphics.TextRenderingHint = TextRenderingHint.AntiAlias;

            var fontSize = pars.SignatureDateFontSize != null ? (float)pars.SignatureDateFontSize : 30;
            using var font = new Font("sans-serif", fontSize);

            var date = GetDate(pars.Language!);
            using var brush = new SolidBrush(Color.FromArgb(48, 48, 48));
            using var sf = new StringFormat();
            sf.LineAlignment = StringAlignment.Center;
            sf.Alignment = StringAlignment.Center;

            var pointX = pars.SignatureDatePositionX != null ? (float)pars.SignatureDatePositionX : 447f;
            var pointY = pars.SignatureDatePositionY != null ? (float)pars.SignatureDatePositionY : 250f;
            graphics.DrawString(date, font, brush, new PointF(pointX, pointY), sf);

            using var imageStream2 = new MemoryStream();
            image.Save(imageStream2, System.Drawing.Imaging.ImageFormat.Png);

            var imageData = ImageDataFactory.Create(imageStream2.ToArray());
            appearance.SetSignatureGraphic(imageData);

            if (debug) Console.WriteLine("Stamp image loaded");
        }

        private static void SetPageRect(PdfSigner signer, SignatureParams pars, PdfSignatureAppearance appearance)
        {
            var pageNr = appearance.GetPageNumber();
            var page = signer.GetDocument().GetPage(pageNr);
            var rot = page.GetRotation();
            var is90 = rot == 90;
            var size = page.GetPageSize();

            var scale = 72f / 25.4f;

            var width0 = pars.SignatureWidthMM != null ? (float)pars.SignatureWidthMM : 58.5f;
            var width = width0 * scale;

            var height0 = pars.SignatureHeightMM != null ? (float)pars.SignatureHeightMM : 23f;
            var height = height0 * scale;

            var left0 = pars.SignatureLeftMM != null ? (float)pars.SignatureLeftMM : 18f;
            var left = left0 * scale;

            var bottom0 = pars.SignatureBottomMM != null ? (float)pars.SignatureBottomMM : 10f;
            var bottom = bottom0 * scale;

            var h = is90 ? width : height;
            var w = is90 ? height : width;
            var x = is90 ? size.GetWidth() - bottom - height : left;
            var y = is90 ? left : bottom;

            appearance.SetPageRect(new iText.Kernel.Geom.Rectangle(x, y, w, h));
        }

        private static Image GetSignatureImage(SignatureParams pars)
        {
            if (pars.SignatureImageBase64 != null)
            {
                var bytes = Convert.FromBase64String(pars.SignatureImageBase64);
                using var stream = new MemoryStream(bytes);
                return Image.FromStream(stream);
            }
            else
            {
                var dancert = pars.IsDancert == true ? "dancert." : "ti.";
                var imagePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logos", "stamp." + dancert + pars.Language + ".png");
                return Image.FromFile(imagePath);
            }
        }

        private static string GetDate(string language)
        {
            var d = DateTime.Now;

            return language switch
            {
                "da" => d.ToString("d. MMMM yyyy", CultureInfo.CreateSpecificCulture("da-DK")),
                "de" => d.ToString("d. MMMM yyyy", CultureInfo.CreateSpecificCulture("de-DE")),
                _ => d.ToString("d MMMM yyyy", CultureInfo.CreateSpecificCulture("en-UK")),
            };
        }

        private static string GetReason(string fullName, string language, bool? isDancert)
        {

            return language switch
            {
                "da" => "Godkendt af " + fullName + " og digitalt signeret af " + (isDancert == true ? "Dancert" : "Teknologisk Institut"),
                "de" => "Genehmigt von " + fullName + " und digital signiert vom " + (isDancert == true ? "Dancert" : "Dänischen Technologischen Institut"),
                _ => "Approved by " + fullName + " and digitally signed by " + (isDancert == true ? "Dancert" : "the Danish Technological Institute"),
            };
        }

        private static void SetupCertChains()
        {
            var parser = new Org.BouncyCastle.X509.X509CertificateParser();

            var intCerFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certificates", "intermediate.cer");
            var intCerData = File.ReadAllBytes(intCerFilePath);
            var intCert = parser.ReadCertificate(intCerData);

            var rootCerFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certificates", "root.cer");
            var rootCerData = File.ReadAllBytes(rootCerFilePath);
            var rootCert = parser.ReadCertificate(rootCerData);

            using var store = new X509Store(StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            var certs = store.Certificates.Where((c) => c.Issuer.Contains("Sectigo"));

            var tiCert = certs.First((c) => c.Subject.Contains("Teknologisk"));
            var tiOcert = parser.ReadCertificate(tiCert.RawData);
            tiChain = new Org.BouncyCastle.X509.X509Certificate[] { tiOcert, intCert, rootCert };

            var danCert = certs.First((c) => c.Subject.Contains("Dancert"));
            var danOcert = parser.ReadCertificate(danCert.RawData);
            danChain = new Org.BouncyCastle.X509.X509Certificate[] { danOcert, intCert, rootCert };
        }

    }
}

