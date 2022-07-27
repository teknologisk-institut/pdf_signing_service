
using System.Net;
using System.Net.Sockets;

namespace PDF_sign
{
    public class Program
    {
        public static void Main()
        {
            var signature = new Signature();

            var output = signature.Sign(@"{

'reason': 'reason ABC',
'location': 'location LOC',
'contact': 'contact DEF',
'signatureCreator': 'signatureCreator HIJ',
'language': 'en',
'pdfBase64': '" + Convert.ToBase64String(File.ReadAllBytes(@"c:\Users\osv\Documents\test.pdf")) + @"'

}");

            File.WriteAllBytes(@"c:\Users\osv\Documents\testYYY.pdf", Convert.FromBase64String(output));
        }

        public static void ListenTCP()
        {
            var signature = new Signature();

            var server = new TcpListener(IPAddress.Any, 9999);

            server.Start();

            while (true)
            {
                var client = server.AcceptTcpClient();

                var ns = client.GetStream();
                var reader = new StreamReader(ns);

                while (client.Connected)
                {
                    var line = reader.ReadLine();
                    if (line == null) continue;

                    var vals = line.Split("|");

                    var data = reader.ReadToEnd();
                }


            };

        }

    }
}

