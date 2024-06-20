// Add-Migration InitalCreate
// Update-Database

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Net;
using System.Net.Sockets;

namespace PDF_sign
{
    public class Program
    {
        public static void Main()
        {
            //ListenTCP(9999);
            ListenTCP(9989);

            //PrintTokens(0);
            //PrintTokens(1);
        }

        static void ListenTCP(int port)
        {
            var signature = new Signature();

            var server = new TcpListener(IPAddress.Any, port);
            server.Start();

            Console.WriteLine(DateTime.Now + " Listening on port " + port);

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
                        var data = signature.Sign(line);
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

        static void PrintTokens(int slotID)
        {
            var factories = new Pkcs11InteropFactories();

            using var pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, @"c:\PDF_SIGN\eTPKCS11.dll", AppType.MultiThreaded);

            var slot = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent)[slotID];

            var slotInfo = slot.GetSlotInfo();

            Console.WriteLine("Slot");
            Console.WriteLine("  Manufacturer:       " + slotInfo.ManufacturerId);
            Console.WriteLine("  Description:        " + slotInfo.SlotDescription);
            Console.WriteLine("  Token present:      " + slotInfo.SlotFlags.TokenPresent);

            if (slotInfo.SlotFlags.TokenPresent)
            {
                // Show basic information about token present in the slot
                Net.Pkcs11Interop.HighLevelAPI.ITokenInfo tokenInfo = slot.GetTokenInfo();

                Console.WriteLine("Token");
                Console.WriteLine("  Manufacturer:       " + tokenInfo.ManufacturerId);
                Console.WriteLine("  Model:              " + tokenInfo.Model);
                Console.WriteLine("  Serial number:      " + tokenInfo.SerialNumber);
                Console.WriteLine("  Label:              " + tokenInfo.Label);

                // Show list of mechanisms (algorithms) supported by the token
                Console.WriteLine("Supported mechanisms: ");
                foreach (CKM mechanism in slot.GetMechanismList())
                {
                    Console.WriteLine("  " + mechanism);
                }

            }
        }
    }


}

