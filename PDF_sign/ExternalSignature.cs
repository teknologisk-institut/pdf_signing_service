using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using iText.Signatures;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.X509;

namespace PDF_sign
{
    delegate byte[] ITISign(byte[] message);

    // The usb device does not allow to export a private key. Therefore we must create
    // an external signature class that will on demand use the usb device to sign data
    internal class ExternalSignature : IExternalSignature
    {
        private readonly ITISign TISign;

        public IX509Certificate[] chain;
        public string subjectDN;

        public ExternalSignature(int slotID)
        {
            var db = new SqlContext();
            var password = db.Auth!.Find("certificate")!.Password!;

            var factories = new Pkcs11InteropFactories();

            var pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, @"C:\Windows\System32\eTPKCS11.dll", AppType.MultiThreaded);

            var slot = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent)[slotID];

            var session = slot.OpenSession(SessionType.ReadOnly);

            session.Login(CKU.CKU_USER, password);

            var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);

            var pKeyAttributes = new List<IObjectAttribute>
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            };

            var key = session.FindAllObjects(pKeyAttributes).FirstOrDefault();
            if (key == null) throw new Exception("Private key not found. Slot = " + slotID);

            SetChain(session);

            this.TISign = (message) => session.Sign(mechanism, key, message);
        }

        public String GetDigestAlgorithmName()
        {
            return DigestAlgorithms.SHA256;
        }

        public String GetSignatureAlgorithmName()
        {
            return "RSA";
        }

        public ISignatureMechanismParams? GetSignatureMechanismParameters()
        {
            return null;
        }

        public byte[] Sign(byte[] message)
        {
            return this.TISign(message);
        }

        private void SetChain(ISession session)
        {
            var certAttributes = new List<IObjectAttribute>
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
            };

            var certs = session.FindAllObjects(certAttributes);

            var certAttributeKeys = new List<CKA>
            {
                CKA.CKA_VALUE,
                CKA.CKA_LABEL
            };

            var parser = new X509CertificateParser();

            List<X509Certificate> x509Certificates = [];

            var certificateAttributes = session.GetAttributeValue(certs[0], certAttributeKeys);
            var certStruct = X509CertificateStructure.GetInstance(certificateAttributes[0].GetValueAsByteArray());
            x509Certificates.Add(new X509Certificate(certStruct));

            this.subjectDN = x509Certificates[0].SubjectDN.ToString();

            var intCerFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certificates", "intermediate.cer");
            var intCerData = File.ReadAllBytes(intCerFilePath);
            x509Certificates.Add(parser.ReadCertificate(intCerData));

            var rootCerFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certificates", "root.cer");
            var rootCerData = File.ReadAllBytes(rootCerFilePath);
            x509Certificates.Add(parser.ReadCertificate(rootCerData));

            this.chain = x509Certificates.Select(x => new X509CertificateBC(x)).ToArray();
        }
    }
}
