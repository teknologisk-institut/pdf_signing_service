// Add-Migration InitalCreate
// Update-Database

using System.Net;
using System.Net.Sockets;

namespace PDF_sign
{
    public class Program
    {
        public static void Main()
        {
            //Test();
            ListenTCP();
        }

        static void Test()
        {
            var pdfPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test.pdf");

            var signature = new Signature();

            var output = signature.Sign(@"{

'appName': 'Test app',
'appSecret': '427646690bb8fa2be1421e2e1292cb30b',
'employeeID': 'OSV',
'employeeFullName': 'Oldrich Svec',
'fileName': 'test.pdf',

'language': 'en',
'pdfBase64': '" + Convert.ToBase64String(File.ReadAllBytes(pdfPath)) + @"'

}");

            if (output.Contains(' ')) Console.WriteLine(output);
            else File.WriteAllBytes(pdfPath.Replace("test.pdf", "test3.pdf"), Convert.FromBase64String(output));
        }

        static void ListenTCP()
        {
            try
            {
                var signature = new Signature();

                var server = new TcpListener(IPAddress.Any, 9999);
                server.Start();

                Console.WriteLine("Listening on port 9999");

                while (true)
                {
                    using var client = server.AcceptTcpClient();
                    if (client == null) continue;

                    using var ns = client.GetStream();
                    ns.ReadTimeout = 10_000;

                    using var reader = new StreamReader(ns);
                    using var writer = new StreamWriter(ns) { AutoFlush = true };

                    while (client.Connected)
                    {
                        try
                        {
                            var line = reader.ReadLine();
                            if (line == null) continue;

                            var data = signature.Sign(line);
                            writer.Write(data);
                            client.Close();
                        }
                        catch
                        {
                            client.Close();
                        }
                    }
                }
            }
            catch
            {
                ListenTCP();
            }
        }
    }
}

