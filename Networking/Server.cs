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
        public TcpListener? serverSocket;
        private Thread? thread;

        private bool stopSignal = false;

        public Server(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
        }

        public void StartServer()
        {
            if (thread != null) return;

            thread = new Thread(_StartServer);
            thread.Start();
        }

        protected void _StartServer()
        {
            try
            {
                serverSocket = new TcpListener(IPAddress.Any, 23488);
                serverSocket.Start();
            }
            catch (SocketException ex)
            {
                serverSocket = new TcpListener(IPAddress.Any, 0);
                serverSocket.Start();
            }

            port = ((IPEndPoint)serverSocket.LocalEndpoint).Port;
            Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.statusPortText.Content = port.ToString(); }));

            try
            {
                // accepting loop
                while (!stopSignal)
                {
                    SetConnected(false);
                    connection = serverSocket.AcceptTcpClient();
                    SetConnected(true);
                    stream = connection.GetStream();

                    this.symmetricKey = EstablishTrust();
                    if (this.symmetricKey == null)
                    {
                        connection.Close();
                        continue;
                    }

                    var result = MessageBox.Show("Klient žiada o pripojenie. Chcete povoliť tomuto zariadeniu sa pripojiť?", "Prichádzajúce pripojenie", MessageBoxButton.YesNo);
                    if (result == MessageBoxResult.No)
                    {
                        connection.Close();
                        continue;
                    }

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

        public void StopServer()
        {
            stopSignal = true;
            serverSocket?.Stop();
        }

        public int? Port { get { return port; } }

        public Thread? GetThread()
        {
            return thread;
        }
    }
}
