
using iText.Kernel.Pdf;
using iText.Signatures;
using PDF_sign;
using System.Security.Cryptography.X509Certificates;

var store = new X509Store(StoreLocation.CurrentUser);
store.Open(OpenFlags.ReadOnly);

var certs = store.Certificates.Where((c) => c.SerialNumber == "00882C5415453EB15DA9E03C1760F7D7A9");

var cert = certs.First();
var pk = cert.GetRSAPrivateKey();

var cp = new Org.BouncyCastle.X509.X509CertificateParser();
var ocert = cp.ReadCertificate(cert.RawData);

var reader = new PdfReader(@"c:\Users\osv\Documents\test.pdf");
var writer = new FileStream(@"c:\Users\osv\Documents\testXXX.pdf", FileMode.Create);

var props = new StampingProperties();

var signer = new PdfSigner(reader, writer, props);

var chain = new Org.BouncyCastle.X509.X509Certificate[] { ocert };

var signature = new Signature(pk);

Task.Run(() =>
{
    Thread.Sleep(1000);
    var sim = new WindowsInput.InputSimulator();
    sim.Keyboard.TextEntry("!10docSign#1");
    sim.Keyboard.KeyPress(WindowsInput.Native.VirtualKeyCode.RETURN);
});

signer.SignDetached(signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

