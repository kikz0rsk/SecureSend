using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace BP
{
    internal class Server
    {
        private int? port;
        private TcpListener? tcpListener;
        private MainWindow mainWindow;

        public Server(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
        }

        public void Start()
        {
            tcpListener = new TcpListener(System.Net.IPAddress.Any, 0);
            tcpListener.Start();
            port = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
            Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.statusPortText.Content = port.ToString(); }));
        }

        public int? Port { get { return port; } }
    }
}
