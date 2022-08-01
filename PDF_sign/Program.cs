
using System.Net;
using System.Net.Sockets;
using Websocket.Client;

namespace PDF_sign
{
    public class Program
    {
        public static void Main()
        {
            //ListenTCP();
            Test();
            //InitWS();
        }

        static void InitWS()
        {
            var exitEvent = new ManualResetEvent(false);

            var url = new Uri("wss://run.yodadev.localdom.net/personal/osv/playground/pdf-sign/ws");

            var client = new WebsocketClient(url, () =>
            {
                var cl = new System.Net.WebSockets.ClientWebSocket();
                cl.Options.SetRequestHeader("Cookie", "auth_jwt_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VySUQiOiJPU1YifQ.I-SYu0HHUlelTWnhBQR6rYIBP5D83T_bJrx_ovofEV0");
                return cl;
            });

            var signature = new Signature();

            client.MessageReceived.Subscribe(msg =>
            {
                var data = signature.Sign(msg.Text);
                client.SendInstant(data);
            });

            client.StartOrFail();

            exitEvent.WaitOne();
        }

        static void Test()
        {
            var pdfPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test.pdf");

            var signature = new Signature();

            var output = signature.Sign(@"{

'reason': 'reason ABC',
'location': 'location LOC',
'contact': 'contact DEF',
'signatureCreator': 'signatureCreator HIJ',
'fileName': 'test.pdf',
'employeeID': 'OSV',
'leftMM': 151.5,
'bottomMM': 267,
'language': 'en',
'pdfBase64': '" + Convert.ToBase64String(File.ReadAllBytes(pdfPath)) + @"'

}");

            File.WriteAllBytes(pdfPath.Replace("test.pdf", "test2.pdf"), Convert.FromBase64String(output));
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

                    if (client.Client.RemoteEndPoint == null)
                    {
                        client.Close();
                        continue;
                    }

                    var ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();

                    if (ip != "127.0.0.1")
                    {
                        client.Close();
                        continue;
                    }

                    using var ns = client.GetStream();
                    using var reader = new StreamReader(ns);
                    using var writer = new StreamWriter(ns) { AutoFlush = true };

                    while (client.Connected)
                    {
                        var line = reader.ReadLine();
                        if (line == null) continue;

                        var data = signature.Sign(line);
                        writer.Write(data);
                        client.Close();
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

