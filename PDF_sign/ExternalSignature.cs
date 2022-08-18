using iText.Signatures;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PDF_sign
{
    // The usb device does not allow to export a private key. Therefore we must create
    // an external signature class that will on demand use the usb device to sign data
    internal class ExternalSignature : IExternalSignature
    {
        readonly RSA Rsa;

        public ExternalSignature(RSA rsa)
        {
            Rsa = rsa;
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
            return Rsa.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}
