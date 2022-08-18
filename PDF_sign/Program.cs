// Add-Migration InitalCreate
// Update-Database

using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace PDF_sign
{
    public class Program
    {
        public static void Main()
        {
            Task.Run(() => PastePassword());
            ListenTCP();
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

        static void PastePassword()
        {
            var db = new SqlContext();
            var password = db.Auth!.Find("certificate")!.Password!;
            db.Dispose();

            while (true)
            {
                var title = GetCaptionOfActiveWindow();

                if (title == "Token Logon")
                {
                    Thread.Sleep(500);

                    var sim = new WindowsInput.InputSimulator();

                    sim.Keyboard.TextEntry(password);
                    sim.Keyboard.KeyPress(WindowsInput.Native.VirtualKeyCode.RETURN);
                }

                Thread.Sleep(500);
            }
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int GetWindowTextLength(IntPtr hWnd);

        private static string GetCaptionOfActiveWindow()
        {
            var strTitle = string.Empty;
            var handle = GetForegroundWindow();
            var intLength = GetWindowTextLength(handle) + 1;
            var stringBuilder = new StringBuilder(intLength);
            if (GetWindowText(handle, stringBuilder, intLength) > 0)
            {
                strTitle = stringBuilder.ToString();
            }
            return strTitle;
        }
    }
}

