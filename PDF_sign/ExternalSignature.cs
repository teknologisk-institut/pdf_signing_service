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
    internal class TokenUnavailableException : Exception
    {
        public TokenUnavailableException(string message) : base(message) { }
    }

    // The usb device does not allow to export a private key. Therefore we must create
    // an external signature class that will on demand use the usb device to sign data
    internal class ExternalSignature : IExternalSignature, IDisposable
    {
        // The PKCS#11 library is loaded once per process and never unloaded. The module
        // is not designed for repeated C_Initialize/C_Finalize cycles while sessions exist.
        private static IPkcs11Library? pkcs11Library;
        private static readonly object libraryLock = new object();

        internal static IPkcs11Library Library
        {
            get
            {
                if (pkcs11Library != null) return pkcs11Library;
                lock (libraryLock)
                {
                    pkcs11Library ??= new Pkcs11InteropFactories().Pkcs11LibraryFactory.LoadPkcs11Library(
                        new Pkcs11InteropFactories(), @"C:\Windows\System32\eTPKCS11.dll", AppType.MultiThreaded);
                    return pkcs11Library;
                }
            }
        }

        // Serial numbers of tokens whose PIN login failed. No further automatic PIN
        // attempts are made for them - QSCD tokens lock permanently after 3 wrong PINs.
        private static readonly HashSet<string> pinFailedSerials = new HashSet<string>();

        public string TokenSerial { get; }

        private ISession? session;
        private IObjectHandle? key;

        public IX509Certificate[] chain;
        public string subjectDN;

        public ExternalSignature(ISlot slot)
        {
            this.TokenSerial = slot.GetTokenInfo().SerialNumber.Trim();

            if (pinFailedSerials.Contains(TokenSerial))
                throw new Exception("PIN for token " + TokenSerial + " failed earlier. No new login attempt will be made until the service is restarted.");

            try
            {
                (session, key) = OpenSession(slot);

                SetChain(session);
            }
            catch
            {
                Dispose();
                throw;
            }
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

        internal bool HasOpenSession => session != null && key != null;

        public byte[] Sign(byte[] message)
        {
            // The warm session may have been lost earlier (token unplugged and put back).
            // Try to reconnect on this request instead of failing forever.
            if (session == null || key == null)
            {
                var reconnectSlot = FindSlotBySerial();
                if (reconnectSlot == null)
                    throw new TokenUnavailableException("Token " + TokenSerial + " (" + subjectDN + ") is not present in any reader.");

                (session, key) = OpenSession(reconnectSlot);
            }

            try
            {
                var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);
                return session.Sign(mechanism, key, message);
            }
            catch (Exception ex) when (IsTokenGone(ex))
            {
                // The token disappeared and (hopefully) came back, e.g. after a USB glitch.
                // Re-open the session on the same token (looked up by serial number, never
                // by slot id - slot ids are reused when readers are re-enumerated) and
                // retry the signature exactly once.
                Console.WriteLine(DateTime.Now + " Session lost for " + subjectDN + " (" + ex.Message + "). Re-opening session and retrying once.");

                Dispose();

                var slot = FindSlotBySerial();
                if (slot == null)
                    throw new TokenUnavailableException("Token " + TokenSerial + " (" + subjectDN + ") is not present in any reader.");

                (session, key) = OpenSession(slot);

                var mechanism2 = session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);
                return session.Sign(mechanism2, key, message);
            }
        }

        public void Dispose()
        {
            try { session?.Dispose(); } catch { }
            session = null;
            key = null;
        }

        private (ISession session, IObjectHandle key) OpenSession(ISlot slot)
        {
            // Single guard for ALL login attempts (constructor + reconnect in Sign).
            if (pinFailedSerials.Contains(TokenSerial))
                throw new Exception("PIN for token " + TokenSerial + " failed earlier. No new login attempt will be made until the service is restarted.");

            var db = new SqlContext();
            var password = db.Auth!.Find("certificate")!.Password!;

            var newSession = slot.OpenSession(SessionType.ReadOnly);

            try
            {
                newSession.Login(CKU.CKU_USER, password);
            }
            catch (Exception ex)
            {
                try { newSession.Dispose(); } catch { }

                if (IsPinError(ex))
                {
                    pinFailedSerials.Add(TokenSerial);
                    throw new Exception("Login with PIN failed for token " + TokenSerial + ": " + ex.Message +
                        ". No further login attempts will be made until the service is restarted.", ex);
                }

                throw;
            }

            var pKeyAttributes = new List<IObjectAttribute>
            {
                newSession.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            };

            var newKey = newSession.FindAllObjects(pKeyAttributes).FirstOrDefault();
            if (newKey == null)
            {
                newSession.Dispose();
                throw new Exception("Private key not found. Token = " + TokenSerial);
            }

            return (newSession, newKey);
        }

        private ISlot? FindSlotBySerial()
        {
            return Library.GetSlotList(SlotsType.WithTokenPresent)
                .FirstOrDefault(s => s.GetTokenInfo().SerialNumber.Trim() == TokenSerial);
        }

        private static bool IsPinError(Exception ex)
        {
            return ex.Message.Contains("CKR_PIN_INCORRECT")
                || ex.Message.Contains("CKR_PIN_INVALID")
                || ex.Message.Contains("CKR_PIN_EXPIRED")
                || ex.Message.Contains("CKR_PIN_LOCKED");
        }

        private static bool IsTokenGone(Exception ex)
        {
            return ex is TokenUnavailableException
                || ex.Message.Contains("CKR_TOKEN_NOT_PRESENT")
                || ex.Message.Contains("CKR_DEVICE_ERROR")
                || ex.Message.Contains("CKR_SESSION_HANDLE_INVALID");
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

            foreach (var cert in certs)
            {
                var certificateAttributes = session.GetAttributeValue(cert, certAttributeKeys);
                var certStruct = X509CertificateStructure.GetInstance(certificateAttributes[0].GetValueAsByteArray());
                var c = new X509Certificate(certStruct);

                if (c.SubjectDN.ToString().Contains(".dk"))
                {
                    x509Certificates.Add(c);
                    break;
                }
            }

            this.subjectDN = x509Certificates[0].SubjectDN.ToString();
            Console.WriteLine(subjectDN);

            var dirName = GetDirName();

            var intCerFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certificates", dirName, "intermediate.cer");
            var intCerData = File.ReadAllBytes(intCerFilePath);
            x509Certificates.Add(parser.ReadCertificate(intCerData));

            var rootCerFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certificates", dirName, "root.cer");
            var rootCerData = File.ReadAllBytes(rootCerFilePath);
            x509Certificates.Add(parser.ReadCertificate(rootCerData));

            this.chain = x509Certificates.Select(x => new X509CertificateBC(x)).ToArray();
        }

        private string GetDirName()
        {
            if (subjectDN.Contains("danfysik", StringComparison.OrdinalIgnoreCase)) return "entrust";

            return "sectigo";
        }
    }
}
