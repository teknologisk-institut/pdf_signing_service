using iText.IO.Font;
using iText.Kernel.Pdf;
using iText.Kernel.XMP.Impl;
using iText.Pdfa;
using iText.Signatures;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System.Net;
using System.Security.Cryptography;
using System.Text;


namespace pdfsign
{
    class AdobeLtvEnabling
    {

        SignatureUtil signatureUtil;
        PdfDocument pdfDocument;
        ISet<X509Certificate?> seenCertificates = new HashSet<X509Certificate?>();
        IDictionary<PdfName, ValidationData> validated = new Dictionary<PdfName, ValidationData>();

        public static List<X509Certificate> extraCertificates = new List<X509Certificate>();

        /**
         * Use this constructor with a {@link PdfStamper} in append mode. Otherwise
         * the existing signatures will be damaged.
         */
        public AdobeLtvEnabling(PdfDocument pdfStamper)
        {
            pdfDocument = pdfStamper;
            signatureUtil = new SignatureUtil(pdfDocument);
        }

        /**
         * Call this method to have LTV information added to the {@link PdfStamper}
         * given in the constructor.
         */
        public void enable(IOcspClient ocspClient, ICrlClient crlClient)
        {
            
            var names = signatureUtil.GetSignatureNames();
            
            foreach (String name in names)
            {
                PdfPKCS7 pdfPKCS7 = signatureUtil.ReadSignatureData(name);
                PdfSignature sig= signatureUtil.GetSignature(name);
                X509Certificate certificate = pdfPKCS7.GetSigningCertificate();
                addLtvForChain(certificate, ocspClient, crlClient, getSignatureHashKey(sig));
            }

            outputDss();
        }

        //
        // the actual LTV enabling methods
        //
        void addLtvForChain(X509Certificate? certificate, IOcspClient ocspClient, ICrlClient crlClient, PdfName key)
        {
            if (certificate != null && seenCertificates.Contains(certificate)) return;

            seenCertificates.Add(certificate);

            ValidationData validationData = new ValidationData();

            while (certificate != null)
            {
                Console.WriteLine(certificate.SubjectDN);
                X509Certificate? issuer = getIssuerCertificate(certificate);
                validationData.certs.Add(certificate.GetEncoded());
                byte[] ocspResponse = ocspClient.GetEncoded(certificate, issuer, null);
                if (ocspResponse != null)
                {
                    Console.WriteLine("  with OCSP response");
                    validationData.ocsps.Add(ocspResponse);
                    X509Certificate? ocspSigner = getOcspSignerCertificate(ocspResponse);
                    if (ocspSigner != null)
                    {
                        Console.WriteLine("  signed by {0}\n", ocspSigner.SubjectDN);
                    }
                    addLtvForChain(ocspSigner, ocspClient, crlClient, getOcspHashKey(ocspResponse));
                }
                else
                {
                    ICollection<byte[]> crl = crlClient.GetEncoded(certificate, null);
                    if (crl != null && crl.Count > 0)
                    {
                        Console.WriteLine("  with {0} CRLs\n", crl.Count);
                        foreach (byte[] crlBytes in crl)
                        {
                            validationData.crls.Add(crlBytes);
                            addLtvForChain(null, ocspClient, crlClient, getCrlHashKey(crlBytes));
                        }
                    }
                }
                certificate = issuer;
            }

            validated[key] = validationData;
        }

        void outputDss()
        {
            PdfWriter writer = pdfDocument.GetWriter();
            PdfReader reader = pdfDocument.GetReader();

            PdfDictionary dss = new PdfDictionary();
            PdfDictionary vrim = new PdfDictionary();
            PdfArray ocsps = new PdfArray();
            PdfArray crls = new PdfArray();
            PdfArray certs = new PdfArray();

            PdfCatalog catalog = pdfDocument.GetCatalog();
            if (pdfDocument.GetPdfVersion().CompareTo(PdfVersion.PDF_2_0) < 0)
            {
                catalog.AddDeveloperExtension(PdfDeveloperExtension.ESIC_1_7_EXTENSIONLEVEL5);
                catalog.AddDeveloperExtension(new PdfDeveloperExtension(PdfName.ADBE, new PdfName("1.7"), 8));
            }

            foreach (PdfName vkey in validated.Keys)
            {
                PdfArray ocsp = new PdfArray();
                PdfArray crl = new PdfArray();
                PdfArray cert = new PdfArray();
                PdfDictionary vri = new PdfDictionary();
                foreach (byte[] b in validated[vkey].crls)
                {
                    PdfStream ps = new PdfStream(b);
                    ps.SetCompressionLevel(CompressionConstants.DEFAULT_COMPRESSION);
                    ps.MakeIndirect(pdfDocument);
                    crl.Add(ps);
                    crls.Add(ps);
                    crls.SetModified();
                }
                foreach (byte[] b in validated[vkey].ocsps)
                {
                    PdfStream ps = new PdfStream(buildOCSPResponse(b));
                    ps.SetCompressionLevel(CompressionConstants.DEFAULT_COMPRESSION);
                    ps.MakeIndirect(pdfDocument);
                    ocsp.Add(ps);
                    ocsps.Add(ps);
                    ocsps.SetModified();
                }
                foreach (byte[] b in validated[vkey].certs)
                {
                    PdfStream ps = new PdfStream(b);
                    ps.SetCompressionLevel(CompressionConstants.DEFAULT_COMPRESSION);
                    ps.MakeIndirect(pdfDocument);
                    cert.Add(ps);
                    certs.Add(ps);
                    certs.SetModified();
                }
                if (ocsp.Size() > 0)
                {
                    ocsp.MakeIndirect(pdfDocument);
                    vri.Put(PdfName.OCSP, ocsp);
                }
                if (crl.Size() > 0)
                {
                    crl.MakeIndirect(pdfDocument);
                    vri.Put(PdfName.CRL, crl);
                }
                if (cert.Size() > 0)
                {
                    cert.MakeIndirect(pdfDocument);
                    vri.Put(PdfName.Cert, cert);
                }
                vri.Put(PdfName.TU, new PdfDate().GetPdfObject());
                vri.MakeIndirect(pdfDocument);
                vrim.Put(vkey, vri);
            }
            vrim.MakeIndirect(pdfDocument);
            vrim.SetModified();
            dss.Put(PdfName.VRI, vrim);
            if (ocsps.Size() > 0)
            {
                ocsps.MakeIndirect(pdfDocument);
                dss.Put(PdfName.OCSPs, ocsps);
            }
            if (crls.Size() > 0)
            {
                crls.MakeIndirect(pdfDocument);
                dss.Put(PdfName.CRLs, crls);
            }
            if (certs.Size() > 0)
            {
                certs.MakeIndirect(pdfDocument);
                dss.Put(PdfName.Certs, certs);
            }

            dss.MakeIndirect(pdfDocument);
            dss.SetModified();
            catalog.Put(PdfName.DSS, dss);
        }

        //
        // VRI signature hash key calculation
        //
        static PdfName getCrlHashKey(byte[] crlBytes)
        {
            X509Crl crl = new X509Crl(CertificateList.GetInstance(crlBytes));
            byte[] signatureBytes = crl.GetSignature();
            DerOctetString octetString = new DerOctetString(signatureBytes);
            byte[] octetBytes = octetString.GetEncoded();
            byte[] octetHash = hashBytesSha1(octetBytes);
            PdfName octetName = new PdfName(ConvertToHex(octetHash));
            return octetName;
        }

        static PdfName getOcspHashKey(byte[] basicResponseBytes)
        {
            BasicOcspResponse basicResponse = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(basicResponseBytes));
            byte[] signatureBytes = basicResponse.Signature.GetBytes();
            DerOctetString octetString = new DerOctetString(signatureBytes);
            byte[] octetBytes = octetString.GetEncoded();
            byte[] octetHash = hashBytesSha1(octetBytes);
            PdfName octetName = new PdfName(ConvertToHex(octetHash));
            return octetName;
        }

        static PdfName getSignatureHashKey(PdfSignature sig)
        {
            PdfString contents = sig.GetContents();
            byte[] bc = PdfEncodings.ConvertToBytes(contents.GetValue(), null);
            byte[] bt = hashBytesSha1(bc);
            return new PdfName(ConvertToHex(bt));
        }

        static byte[] hashBytesSha1(byte[] b)
        {
            SHA1 sha = new SHA1CryptoServiceProvider();
            return sha.ComputeHash(b);
        }

        static String ConvertToHex(byte[] bytes)
        {
            var buf = new iText.IO.Source.ByteBuffer();
            foreach (byte b in bytes)
            {
                buf.AppendHex(b);
            }
            return PdfEncodings.ConvertToString(buf.ToByteArray(), null).ToUpperInvariant();
        }

        //
        // OCSP response helpers
        //
        static X509Certificate? getOcspSignerCertificate(byte[] basicResponseBytes)
        {
            BasicOcspResponse borRaw = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(basicResponseBytes));
            BasicOcspResp bor = new BasicOcspResp(borRaw);

            var certs = bor.GetCerts().ToArray();

            foreach (X509Certificate x509Certificate in certs)
            {
                if (bor.Verify(x509Certificate.GetPublicKey()))
                    return x509Certificate;
            }

            return null;
        }

        static byte[] buildOCSPResponse(byte[] BasicOCSPResponse)
        {
            DerOctetString doctet = new DerOctetString(BasicOCSPResponse);
            Asn1EncodableVector v2 = new Asn1EncodableVector();
            v2.Add(OcspObjectIdentifiers.PkixOcspBasic);
            v2.Add(doctet);
            DerEnumerated den = new DerEnumerated(0);
            Asn1EncodableVector v3 = new Asn1EncodableVector();
            v3.Add(den);
            v3.Add(new DerTaggedObject(true, 0, new DerSequence(v2)));
            DerSequence seq = new DerSequence(v3);
            return seq.GetEncoded();
        }

        //
        // X509 certificate related helpers
        //
        static X509Certificate? getIssuerCertificate(X509Certificate certificate)
        {
            String? url = getCACURL(certificate);
            if (url != null && url.Length > 0)
            {
                HttpWebRequest con = (HttpWebRequest)WebRequest.Create(url);
                HttpWebResponse response = (HttpWebResponse)con.GetResponse();
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new IOException("invalid.http.response.1" + (int)response.StatusCode);
                //Get Response
                Stream inp = response.GetResponseStream();
                byte[] buf = new byte[1024];
                MemoryStream bout = new MemoryStream();
                while (true)
                {
                    int n = inp.Read(buf, 0, buf.Length);
                    if (n <= 0)
                        break;
                    bout.Write(buf, 0, n);
                }
                inp.Close();

                var cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(bout.ToArray());

                return new X509Certificate(X509CertificateStructure.GetInstance(cert2.GetRawCertData()));
            }

            try
            {
                certificate.Verify(certificate.GetPublicKey());
                return null;
            }
            catch
            {
            }

            foreach (X509Certificate candidate in extraCertificates)
            {
                try
                {
                    certificate.Verify(candidate.GetPublicKey());
                    return candidate;
                }
                catch
                {
                }
            }

            return null;
        }

        static String? getCACURL(X509Certificate certificate)
        {
            try
            {
                Asn1Object? obj = getExtensionValue(certificate, X509Extensions.AuthorityInfoAccess.Id);
                if (obj == null)
                {
                    return null;
                }

                Asn1Sequence AccessDescriptions = (Asn1Sequence)obj;
                for (int i = 0; i < AccessDescriptions.Count; i++)
                {
                    Asn1Sequence AccessDescription = (Asn1Sequence)AccessDescriptions[i];
                    if (AccessDescription.Count != 2)
                    {
                        continue;
                    }
                    else
                    {
                        if ((AccessDescription[0] is DerObjectIdentifier) && ((DerObjectIdentifier)AccessDescription[0]).Id.Equals("1.3.6.1.5.5.7.48.2"))
                        {
                            String AccessLocation = getStringFromGeneralName((Asn1Object)AccessDescription[1]);
                            return AccessLocation == null ? "" : AccessLocation;
                        }
                    }
                }
            }
            catch
            {
            }
            return null;
        }

        static Asn1Object? getExtensionValue(X509Certificate certificate, String oid)
        {
            byte[] bytes = certificate.GetExtensionValue(new DerObjectIdentifier(oid)).GetDerEncoded();
            if (bytes == null)
            {
                return null;
            }
            Asn1InputStream aIn = new Asn1InputStream(new MemoryStream(bytes));
            Asn1OctetString octs = (Asn1OctetString)aIn.ReadObject();
            aIn = new Asn1InputStream(new MemoryStream(octs.GetOctets()));
            return aIn.ReadObject();
        }

        private static String getStringFromGeneralName(Asn1Object names)
        {
            Asn1TaggedObject taggedObject = (Asn1TaggedObject)names;
            return Encoding.GetEncoding(1252).GetString(Asn1OctetString.GetInstance(taggedObject, false).GetOctets());
        }

        //
        // inner class
        //
        class ValidationData
        {
            public IList<byte[]> crls = new List<byte[]>();
            public IList<byte[]> ocsps = new List<byte[]>();
            public IList<byte[]> certs = new List<byte[]>();
        }

    }
}
