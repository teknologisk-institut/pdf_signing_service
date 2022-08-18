
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.IO.Image;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using System.Drawing;
using System.Globalization;
using System.Drawing.Text;
using System.Security.Cryptography;

namespace PDF_sign
{
    public class Signature
    {
        private static ExternalSignature? signature;
        private static Org.BouncyCastle.X509.X509Certificate[]? chain;

        private static readonly SHA256 sha = SHA256.Create();

        private static readonly bool debug = false;

        public static void SetupSignature()
        {
            using var store = new X509Store(StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            var certs = store.Certificates.Where((c) => c.SerialNumber == "00882C5415453EB15DA9E03C1760F7D7A9");

            using var cert = certs.First();
            var pk = cert.GetRSAPrivateKey();
            if (pk == null) throw new Exception("Private key not found");

            signature = new ExternalSignature(pk);

            var cp = new Org.BouncyCastle.X509.X509CertificateParser();
            var ocert = cp.ReadCertificate(cert.RawData);

            chain = new Org.BouncyCastle.X509.X509Certificate[] { ocert };
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
                    LeftMM = pars.LeftMM,
                    BottomMM = pars.BottomMM,
                });

                db.SaveChanges();

                if (debug) Console.WriteLine("File returned");

                return Convert.ToBase64String(arr);
            }
            catch (Exception ex)
            {
                signature = null;
                chain = null;
                return ex.Message;
            }
        }

        internal static byte[] PerformSigning(SignatureParams pars)
        {
            if (signature == null || chain == null) SetupSignature();

            var pdf = Convert.FromBase64String(pars.PdfBase64!);
            using var inputStream = new MemoryStream(pdf);
            using var reader = new PdfReader(inputStream);

            var props = new StampingProperties();

            using var outputStream = new MemoryStream();
            var signer = new PdfSigner(reader, outputStream, props);

            var appearance = signer.GetSignatureAppearance();
            appearance.SetReason(GetReason(pars.EmployeeFullName!, pars.Language!));
            appearance.SetLocation("Gregersensvej 1, 2630 Taastrup, Denmark");
            appearance.SetContact("Phone: +4572202000, E-mail: info@teknologisk.dk");
            appearance.SetSignatureCreator(pars.AppName + " (" + pars.EmployeeID + ")");

            if (pars.NoVisualSignature != true) SetVisualSignature(appearance, pars);
            
            var tsa = new TSAClientBouncyCastle("http://timestamp.digicert.com", "", "");

            var ocspVerifier = new OCSPVerifier(null, null);
            var ocspClient = new OcspClientBouncyCastle(ocspVerifier);
            var crlClients = new List<ICrlClient>(new[] { new CrlClientOnline() });

            signer.SignDetached(signature, chain, null, ocspClient, tsa, 0, PdfSigner.CryptoStandard.CMS);

            if (debug) Console.WriteLine("File signed");

            var arr = outputStream.ToArray();
            return arr;
        }

        private static void SetVisualSignature(PdfSignatureAppearance appearance, SignatureParams pars)
        {
            appearance.SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            appearance.SetPageNumber(1);

            var width = 58.5f * 72f / 25.4f;
            var height = 23f * 72f / 25.4f;
            var left0 = pars.LeftMM != null ? (float)pars.LeftMM : 18f;
            var left = left0 * 72f / 25.4f;
            var bottom0 = pars.BottomMM != null ? (float)pars.BottomMM : 10f;
            var bottom = bottom0 * 72f / 25.4f;
            appearance.SetPageRect(new iText.Kernel.Geom.Rectangle(left, bottom, width, height));

            if (debug) Console.WriteLine("Signature info created");

            var imagePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logos", "stamp." + pars.Language + ".png");
            using var image = Image.FromFile(imagePath);
            using var graphics = Graphics.FromImage((Bitmap)image);
            graphics.TextRenderingHint = TextRenderingHint.AntiAlias;
            using var font = new Font("sans-serif", 30);

            var date = GetDate(pars.Language!);
            using var brush = new SolidBrush(Color.FromArgb(48, 48, 48));
            using var sf = new StringFormat();
            sf.LineAlignment = StringAlignment.Center;
            sf.Alignment = StringAlignment.Center;
            graphics.DrawString(date, font, brush, new PointF(447f, 250f), sf);

            using var imageStream2 = new MemoryStream();
            image.Save(imageStream2, System.Drawing.Imaging.ImageFormat.Png);

            var imageData = ImageDataFactory.Create(imageStream2.ToArray());
            appearance.SetSignatureGraphic(imageData);

            if (debug) Console.WriteLine("Stamp image loaded");
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

        private static string GetReason(string fullName, string language)
        {

            return language switch
            {
                "da" => "Godkendt af " + fullName + " og digitalt signeret af Teknologisk Institut",
                "de" => "Genehmigt von " + fullName + " und digital signiert vom Dänischen Technologischen Institut",
                _ => "Approved by " + fullName + " and digitally signed by the Danish Technological Institute",
            };
        }

    }
}

