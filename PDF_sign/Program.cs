
using System.Net;
using System.Net.Sockets;

namespace PDF_sign
{
    public class Program
    {
        public static void Main()
        {
            ListenTCP();
            //Test();
        }

        public static void Test()
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

            Console.WriteLine("Listening on port 9999");

            while (true)
            {
                using var client = server.AcceptTcpClient();

                using var ns = client.GetStream();
                using var reader = new StreamReader(ns);
                using var writer = new StreamWriter(ns);

                while (client.Connected)
                {
                    var line = reader.ReadLine();
                    if (line == null) continue;

                    var data = signature.Sign(line);
                    writer.WriteLine(data);
                }
            }
        }
    }
}

