
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.IO.Image;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using System.Drawing;
using System.Globalization;
using System.Drawing.Text;

namespace PDF_sign
{
    public class Signature
    {
        private readonly ExternalSignature signature;
        private readonly Org.BouncyCastle.X509.X509Certificate[] chain;

        public Signature()
        {
            using var store = new X509Store(StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            var certs = store.Certificates.Where((c) => c.SerialNumber == "00882C5415453EB15DA9E03C1760F7D7A9");

            using var cert = certs.First();
            var pk = cert.GetRSAPrivateKey();
            signature = new ExternalSignature(pk);

            var cp = new Org.BouncyCastle.X509.X509CertificateParser();
            var ocert = cp.ReadCertificate(cert.RawData);

            chain = new Org.BouncyCastle.X509.X509Certificate[] { ocert };
        }

        public string Sign(string json)
        {
            try
            {
                var pars = JsonConvert.DeserializeObject<SignatureParams>(json);

                if (pars == null) throw new Exception("Wrong parameters: " + json);

                if (pars.language == null) pars.language = "en";

                if (pars.language != "en" && pars.language != "da" && pars.language != "de")
                {
                    throw new Exception("Unsupported language: " + pars.language);
                }

                if (pars.pdfBase64 == null) throw new Exception("Missing property: pdfBase64");

                var pdf = Convert.FromBase64String(pars.pdfBase64);
                using var inputStream = new MemoryStream(pdf);
                using var reader = new PdfReader(inputStream);

                var props = new StampingProperties();

                using var outputStream = new MemoryStream();
                var signer = new PdfSigner(reader, outputStream, props);

                var appearance = signer.GetSignatureAppearance();
                if (pars.reason != null) appearance.SetReason(pars.reason);
                if (pars.location != null) appearance.SetLocation(pars.location);
                if (pars.contact != null) appearance.SetContact(pars.contact);
                appearance.SetSignatureCreator("iText®");
                appearance.SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
                appearance.SetPageNumber(1);

                var width = 58.5f * 72f / 25.4f;
                var height = 23f * 72f / 25.4f;
                var left0 = pars.leftMM != null ? (float)pars.leftMM : 18f;
                var left = left0 * 72f / 25.4f;
                var bottom0 = pars.bottomMM != null ? (float)pars.bottomMM : 10f;
                var bottom = bottom0 * 72f / 25.4f;
                appearance.SetPageRect(new iText.Kernel.Geom.Rectangle(left, bottom, width, height));

                var imagePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logos", "stamp." + pars.language + ".png");
                using var image = Image.FromFile(imagePath);
                using var graphics = Graphics.FromImage((Bitmap)image);
                graphics.TextRenderingHint = TextRenderingHint.AntiAlias;
                using var font = new Font("sans-serif", 30);

                var date = GetDate(pars.language);
                using var brush = new SolidBrush(Color.FromArgb(48, 48, 48));
                using var sf = new StringFormat();
                sf.LineAlignment = StringAlignment.Center;
                sf.Alignment = StringAlignment.Center;
                graphics.DrawString(date, font, brush, new PointF(447f, 250f), sf);

                using var imageStream2 = new MemoryStream();
                image.Save(imageStream2, System.Drawing.Imaging.ImageFormat.Png);

                var imageData = ImageDataFactory.Create(imageStream2.ToArray());
                appearance.SetSignatureGraphic(imageData);

                var appID = GetForegroundWindow();

                Task.Run(() =>
                {
                    while (GetForegroundWindow() == appID) Thread.Sleep(50);

                    var sim = new WindowsInput.InputSimulator();
                    sim.Keyboard.TextEntry("!10docSign#1");
                    sim.Keyboard.KeyPress(WindowsInput.Native.VirtualKeyCode.RETURN);
                });

                var tsa = new TSAClientBouncyCastle("http://timestamp.digicert.com", "", "");

                signer.SignDetached(signature, chain, null, null, tsa, 0, PdfSigner.CryptoStandard.CMS);

                var arr = outputStream.ToArray();

                return Convert.ToBase64String(arr);
            }
            catch (Exception ex)
            {
                return ex.Message;
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

        [DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
        private static extern IntPtr GetForegroundWindow();
    }
}

