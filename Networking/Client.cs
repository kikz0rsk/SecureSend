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
using System.Windows;
using Packet = BP.Protocol.Packet;

namespace BP.Networking
{
    internal class Client : NetworkEndpoint
    {
        private string ipAddress;
        private string port;
        public TcpClient connection;

        public Client(string ipAddress, string port, MainWindow mainWindow)
        {
            this.ipAddress = ipAddress;
            this.port = port;
            this.mainWindow = mainWindow;
        }

        public void Start()
        {
            try
            {
                connection = new TcpClient();
                connection.Connect(IPAddress.Parse(ipAddress), int.Parse(port));
                stream = connection.GetStream();

                this.symmetricKey = EstablishTrust();
                if (this.symmetricKey == null)
                {
                    connection.Close();
                    Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.statusText.Content = "Failed to establish trust"; }));
                    return;
                }

                Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.currentConnectionText.Content = "Pripojené"; }));
                CommunicationLoop();
            }
            catch (ThreadInterruptedException inter)
            {
                connection.Close();
            }
        }

        private void CommunicationLoop()
        {
            while (true)
            {
                if (stream.DataAvailable)
                {
                    Packet? packet = ReceivePacket();

                    if (packet == null)
                    {
                        throw new InvalidDataException("Data available in stream but failed to get packet");
                    }

                    if (packet.GetType() != Packet.Type.FILE_INFO)
                    {
                        throw new InvalidDataException("Invalid packet type, expected file info");
                    }

                    GetFile((FileInfoPacket)packet);
                }
                else if (filesToSend.Count > 0)
                {
                    SendFile();
                }
                else
                {
                    Thread.Sleep(100);
                }
            }
        }
    }
}
