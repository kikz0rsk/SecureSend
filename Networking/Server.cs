using BP.Protocol;
using NSec.Cryptography;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Shapes;
using System.Windows.Threading;
using Path = System.IO.Path;

namespace BP.Networking
{
    internal class Server : NetworkEndpoint
    {

        private int? port;

        public TcpListener? tcpListener;

        private TcpClient? connection;
        

        public Server(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
        }

        public void Start()
        {
            try
            {
                tcpListener = new TcpListener(IPAddress.Any, 23488);
                tcpListener.Start();
            }
            catch (SocketException ex)
            {
                tcpListener = new TcpListener(IPAddress.Any, 0);
                tcpListener.Start();
            }

            port = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
            Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.statusPortText.Content = port.ToString(); }));

            try
            {
                // accepting loop
                while (true)
                {
                    Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.currentConnectionText.Content = "Žiadne spojenie"; }));
                    connection = tcpListener.AcceptTcpClient();
                    stream = connection.GetStream();

                    this.symmetricKey = EstablishTrust();
                    if (this.symmetricKey == null)
                    {
                        connection.Close();
                        continue;
                    }
                    Application.Current.Dispatcher.Invoke(new Action(() => {
                        mainWindow.statusPortText.Content = Convert.ToBase64String(symmetricKey.Export(KeyBlobFormat.RawSymmetricKey));
                    }));

                    Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.currentConnectionText.Content = "Pripojené"; }));
                    CommunicationLoop();
                }
            }
            catch (ThreadInterruptedException inter)
            {

            }
            catch (SocketException ex)
            {
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

                    if(packet.GetType() != Packet.Type.FILE_INFO)
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

                    if(dataPacket == null || dataPacket.GetType() != Packet.Type.DATA)
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

        public int? Port { get { return port; } }

        
    }
}
