
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.IO.Image;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using iText.Kernel.Geom;

namespace PDF_sign
{
    public class Signature
    {
        private readonly ExternalSignature signature;
        private readonly Org.BouncyCastle.X509.X509Certificate[] chain;

        public Signature()
        {
            var store = new X509Store(StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            var certs = store.Certificates.Where((c) => c.SerialNumber == "00882C5415453EB15DA9E03C1760F7D7A9");

            var cert = certs.First();
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
            var inputStream = new MemoryStream(pdf);
            var reader = new PdfReader(inputStream);

            var props = new StampingProperties();

            var outputStream = new MemoryStream();
            var signer = new PdfSigner(reader, outputStream, props);

            var appearance = signer.GetSignatureAppearance();
            appearance.SetReason(pars.reason);
            appearance.SetLocation(pars.location);
            appearance.SetContact(pars.contact);
            appearance.SetLocationCaption(pars.locationCaption);
            appearance.SetReasonCaption(pars.reasonCaption);
            appearance.SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            appearance.SetPageNumber(1);
            appearance.SetPageRect(new Rectangle(36, 648, 200, 100));

           // var n2 = appearance.GetLayer2();
            
            var image = Convert.FromBase64String(pars.imageBase64);
            var imageData = ImageDataFactory.Create(image);
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

            inputStream.Close();
            reader.Close();
            outputStream.Close();

            return Convert.ToBase64String(arr);
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
        private static extern IntPtr GetForegroundWindow();
    }
}

