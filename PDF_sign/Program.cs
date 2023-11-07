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
            //var bytes = File.ReadAllBytes("c:\\Users\\osv\\Downloads\\2testik.pdf");
            //var bytes2 = Signature.PerformLTV(bytes);
            //File.WriteAllBytes("c:\\Users\\osv\\Downloads\\xxx.pdf", bytes2);
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
                var windowFound = BringToFront("Token Logon");

                if (windowFound)
                {
                    Thread.Sleep(500);

                    var sim = new WindowsInput.InputSimulator();

                    sim.Keyboard.TextEntry(password);
                    sim.Keyboard.KeyPress(WindowsInput.Native.VirtualKeyCode.RETURN);

                    Log("Logon window filled");

                    Thread.Sleep(1000);
                }

                Thread.Sleep(500);
            }
        }

        private static bool BringToFront(string title)
        {
            var handle = FindWindow(null, title);

            if (handle == IntPtr.Zero) return false;
            else {
                Log("Logon window found " + handle);

                // minimize all windows
                var lHwnd = FindWindow("Shell_TrayWnd", null);
                const int WM_COMMAND = 0x111;
                const int MIN_ALL = 419;
                SendMessage(lHwnd, WM_COMMAND, (IntPtr)MIN_ALL, IntPtr.Zero);

                SetForegroundWindow(handle);

                return true;
            }
        }

        private static void Log(string text)
        {
            var line = DateTime.Now.ToUniversalTime() + " " + text + "\n";
            File.AppendAllText("C:\\PDF_SIGN\\log.txt",  line);
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr FindWindow(String? lpClassName, String? lpWindowName);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr SendMessage(IntPtr hWnd, Int32 Msg, IntPtr wParam, IntPtr lParam);
    }
}

