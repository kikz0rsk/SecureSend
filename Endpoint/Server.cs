﻿using BP.GUI;
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

namespace BP.Endpoint
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
            Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.statusPortText.Content = "Port pre pripojenie: " + port.ToString(); }));

            while (!stopSignal)
            {
                try
                {
                    filesToSend.Clear();
                    // accepting loop
                    SetConnected(false);
                    connection = serverSocket.AcceptTcpClient();
                    this.isClient = false;
                    SetConnected(true);
                    stream = connection.GetStream();

                    this.symmetricKey = EstablishTrust();
                    if (this.symmetricKey == null)
                    {
                        connection.Close();
                        Task.Run(() =>
                        {
                            MessageBox.Show("Nepodarilo sa nadviazať spoločný šifrovací kľúč.", "Chyba pri pripájaní klienta",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                        });
                        continue;
                    }

                    IPEndPoint endpoint = connection.Client.RemoteEndPoint as IPEndPoint;
                    AcceptConnectionResult result = Application.Current.Dispatcher.Invoke(() =>
                    {
                        AcceptConnection acceptConnection = new AcceptConnection(false,
                        new DeviceId(endpoint.Address.ToString(), remoteEndpointPublicKey));
                        acceptConnection.ShowDialog();
                        return acceptConnection.Result;
                    });

                    if (result == AcceptConnectionResult.AcceptOnce ||
                        result == AcceptConnectionResult.AcceptAndRemember)
                    {
                        SendPacket(new AckPacket());
                    }
                    else
                    {
                        Disconnect();
                        continue;
                    }

                    try
                    {
                        Packet? packet = ReceivePacket();
                        if (packet == null || packet.GetType() != Packet.Type.ACK)
                        {
                            throw new InvalidDataException();
                        }
                    }
                    catch (Exception ex)
                    {
                        Task.Run(() =>
                        {
                            MessageBox.Show("Užívateľ odmietol žiadosť o pripojenie.", "Spojenie bolo odmietnuté",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                        });
                        continue;
                    }

                    CommunicationLoop();

                }
                catch (ThreadInterruptedException inter)
                {
                    throw inter;
                }
                catch (SocketException ex)
                {
                }
            }
        }

        public void StopServer()
        {
            Disconnect();
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