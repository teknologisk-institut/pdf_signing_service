
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
            var pars = JsonConvert.DeserializeObject<SignatureParams>(json);

            var pdf = Convert.FromBase64String(pars.pdfBase64);
            using var inputStream = new MemoryStream(pdf);
            using var reader = new PdfReader(inputStream);

            var props = new StampingProperties();

            using var outputStream = new MemoryStream();
            var signer = new PdfSigner(reader, outputStream, props);

            var appearance = signer.GetSignatureAppearance();
            appearance.SetReason(pars.reason);
            appearance.SetLocation(pars.location);
            appearance.SetContact(pars.contact);
            appearance.SetSignatureCreator(pars.signatureCreator);
            appearance.SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            appearance.SetPageNumber(1);

            var width = 58f * 72f / 25.4f;
            var height = 22.8f * 72f / 25.4f;
            var left = 18f * 72f / 25.4f;
            var top = 10f * 72f / 25.4f;
            appearance.SetPageRect(new iText.Kernel.Geom.Rectangle(left, top, width, height));

            var imagePath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logos", "stamp." + pars.language + ".png");
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

            signer.SignDetached(signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

            var arr = outputStream.ToArray();

            return Convert.ToBase64String(arr);
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

