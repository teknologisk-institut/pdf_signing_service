using iText.Signatures;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
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

            var pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, @"C:\Windows\System32\eTPKCS11.dll", AppType.MultiThreaded);

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

            this.TISign = (message) =>
            {
                var response = session.Sign(mechanism, key, message);
                VerifyResponse(message, response, session, mechanism);
                return response;
            };
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

        private void VerifyResponse(byte[] message, byte[] response, ISession session, IMechanism mechanism)
        {

            var publicKeyObjectAttributes = new List<IObjectAttribute>
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            };

            var publicKey = session.FindAllObjects(publicKeyObjectAttributes).FirstOrDefault();
            if (publicKey == null) throw new Exception("Public key not found.");

            session.Verify(mechanism, publicKey, message, response, out bool isValidSignature);

            Console.WriteLine("verify " + isValidSignature);

            if (isValidSignature == false) throw new Exception("VerifyResponse failed");

        }
    }
}
