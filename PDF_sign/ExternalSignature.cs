using iText.Signatures;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace PDF_sign
{
    delegate byte[] ITISign(byte[] message);

    // The usb device does not allow to export a private key. Therefore we must create
    // an external signature class that will on demand use the usb device to sign data
    internal class ExternalSignature : IExternalSignature
    {
        private readonly ITISign TISign;

        public ExternalSignature(int slotID)
        {
            var db = new SqlContext();
            var password = db.Auth!.Find("certificate")!.Password!;

            var factories = new Pkcs11InteropFactories();

            var pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, @"c:\PDF_SIGN\eTPKCS11.dll", AppType.MultiThreaded);

            var slot = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent)[slotID];

            var session = slot.OpenSession(SessionType.ReadOnly);

            session.Login(CKU.CKU_USER, password);

            var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);

            var objectAttributes = new List<IObjectAttribute>
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            };

            var key = session.FindAllObjects(objectAttributes).FirstOrDefault();
            if (key == null) throw new Exception("Certificate not found. Slot = " + slotID);

            this.TISign = (message) => session.Sign(mechanism, key, message);

        }

        public String GetHashAlgorithm()
        {
            return DigestAlgorithms.SHA256;
        }

        public String GetEncryptionAlgorithm()
        {
            return "RSA";
        }

        public byte[] Sign(byte[] message) 
        {
            return this.TISign(message);
        }
    }
}
