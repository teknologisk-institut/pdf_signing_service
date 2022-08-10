// Add-Migration InitalCreate
// Update-Database

using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace PDF_sign
{
    public class Program
    {
        public static void Main()
        {
            WarmUp();
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

        static void WarmUp()
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

            var appID = GetForegroundWindow();

            var taskController = new CancellationTokenSource();
            var token = taskController.Token;

            using var task = Task.Run(() =>
            {
                while (!token.IsCancellationRequested && GetForegroundWindow() == appID) Thread.Sleep(50);

                var sim = new WindowsInput.InputSimulator();

                sim.Keyboard.TextEntry(password);
                sim.Keyboard.KeyPress(WindowsInput.Native.VirtualKeyCode.RETURN);
            });

            var bytes = Signature.PerformSigning(pars, password);

            taskController.Cancel();

            Console.WriteLine("Warmed up: " + bytes.Length);
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
        private static extern IntPtr GetForegroundWindow();
    }
}

