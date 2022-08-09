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

            var output = Signature.Sign(@"{

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
            StartPing();

            var server = new TcpListener(IPAddress.Any, 9999);
            server.Start();

            Console.WriteLine("Listening on port 9999");

            while (true)
            {
                using var client = server.AcceptTcpClient();

                try
                {
                    client.ReceiveTimeout = 10_000;
                    client.SendTimeout = 10_000;

                    using var ns = client.GetStream();
                    using var reader = new StreamReader(ns);
                    using var writer = new StreamWriter(ns) { AutoFlush = true };

                    var line = reader.ReadLine();

                    if (line != null)
                    {
                        var data = Signature.Sign(line);
                        writer.Write(data);
                    }
                }
                catch { }
                finally
                {
                    client.Close();
                }
            }
        }

        static void StartPing()
        {
            var pdfPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test.pdf");

            var pars = new SignatureParams
            {
                Language = "EN",
                PdfBase64 = Convert.ToBase64String(File.ReadAllBytes(pdfPath))
            };

            var db = new SqlContext();
            var password = db.Auth!.Find("certificate")!.Password!;
            db.Dispose();

            Task.Run(async () =>
            {
                var sign = Task.Run(() => Signature.PerformSigning(pars, password));
                var timeout = Task.Delay(TimeSpan.FromSeconds(10));
                var result = await Task.WhenAny(sign, timeout);

                if (result == timeout) Environment.Exit(0);
                else Thread.Sleep(3600_000);
            });
        }
    }
}

