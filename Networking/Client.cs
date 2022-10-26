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
                    Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.statusPortText.Content = "Failed to establish trust"; }));
                    return;
                }
                Application.Current.Dispatcher.Invoke(new Action(() => {
                    mainWindow.statusPortText.Content = Convert.ToBase64String(symmetricKey.Export(KeyBlobFormat.RawSymmetricKey));
                }));

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

        private void SendFile()
        {
            string filepath;
            if (!filesToSend.TryDequeue(out filepath))
            {
                return;
            }

            if (!File.Exists(filepath)) return;

            ulong totalBytes = (ulong)new FileInfo(filepath).Length;
            FileInfoPacket fileInfoPacket = new FileInfoPacket(Path.GetFileName(filepath), totalBytes);
            SendPacket(fileInfoPacket);

            using (Stream fileStream = File.OpenRead(filepath))
            {
                byte[] buffer = new byte[40_000];
                int bytesRead;
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    DataPacket data = new DataPacket(buffer.Take(bytesRead).ToArray());
                    SendPacket(data);
                }
            }
        }

        private void GetFile(FileInfoPacket fileInfo)
        {
            Application.Current.Dispatcher.Invoke(new Action(() => {
                mainWindow.statusPortText.Content = "Incoming file: " + fileInfo.GetFileName();
                mainWindow.fileProgressBar.Value = 0;
            }));

            ulong totalBytes = fileInfo.GetFileSize();
            using (FileStream fileStream = new FileStream(fileInfo.GetFileName(), FileMode.Create))
            {
                ulong bytesWritten = 0;
                while (bytesWritten < totalBytes)
                {
                    Packet? dataPacket = ReceivePacket();

                    if (dataPacket == null || dataPacket.GetType() != Packet.Type.DATA)
                    {
                        throw new InvalidDataException("GetFile() received invalid packet");
                    }

                    byte[] data = ((DataPacket)dataPacket).GetData();

                    fileStream.Write(data);
                    bytesWritten += (ulong)data.Length;
                    Application.Current.Dispatcher.Invoke(new Action(() => {
                        mainWindow.fileProgressBar.Value = (bytesWritten / totalBytes);
                    }));
                }
            }

            Application.Current.Dispatcher.Invoke(new Action(() => {
                mainWindow.fileProgressBar.Value = 100;
            }));
        }
    }
}
