using BP.Protocol;
using NSec.Cryptography;
using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Packet = BP.Protocol.Packet;

namespace BP.Networking
{
    internal class Client : NetworkEndpoint
    {
        private string? ipAddress;
        private string? port;
        protected Thread? thread;

        public Client(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
        }

        public void Connect(string ipAddress, string port)
        {
            this.ipAddress = ipAddress;
            this.port = port;

            thread = new Thread(_Connect);
            thread.Start();
        }

        protected void _Connect()
        {
            try
            {
                connection = new TcpClient();
                connection.Connect(IPAddress.Parse(ipAddress), int.Parse(port));
                this.isClient = true;
                stream = connection.GetStream();

                this.symmetricKey = EstablishTrust();
                if (this.symmetricKey == null)
                {
                    connection.Close();
                    Task.Run(() =>
                    {
                        MessageBox.Show("Nepodarilo sa nadviazať spoločný šifrovací kľúč.", "Chyba pri pripájaní k serveru",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                    return;
                }

                SetConnected(true);
                CommunicationLoop();
            }
            catch (ThreadInterruptedException inter)
            {
                connection?.Close();
            }
            SetConnected(false);
        }

        public Thread? GetThread()
        {
            return thread;
        }
    }
}
