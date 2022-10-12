using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace BP
{
    internal class Server
    {
        private MainWindow mainWindow;

        private int? port;

        public TcpListener? tcpListener;

        private TcpClient connection;
        private NetworkStream connectionStream;
        private Key symmetricKey;


        public Server(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
        }

        public void Start()
        {
            try
            {
                tcpListener = new TcpListener(System.Net.IPAddress.Any, 23488);
                tcpListener.Start();
            } catch(SocketException ex)
            {
                tcpListener = new TcpListener(System.Net.IPAddress.Any, 0);
                tcpListener.Start();
            }
            
            port = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
            Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.statusPortText.Content = port.ToString(); }));

            try
            {
                // accepting loop
                while (true)
                {
                    connection = tcpListener.AcceptTcpClient();
                    connectionStream = connection.GetStream();

                    Key? key = EstablishTrust();
                    if (key == null)
                    {
                        connection.Close();
                        continue;
                    }

                    CommunicationLoop();
                }
            } catch (ThreadInterruptedException inter)
            {

            } catch (SocketException ex)
            {
            }
        }

        private void CommunicationLoop()
        {
            while(true)
            {
                
            }
        }

        public int? Port { get { return port; } }

        private Key? EstablishTrust()
        {
            // send public key
            connectionStream.Write(mainWindow.ClientKeyPair.PublicKey.Export(KeyBlobFormat.RawPublicKey), 0, 32);

            // get client's public key
            byte[] clientPublicKeyRaw = new byte[32];
            connectionStream.Read(clientPublicKeyRaw, 0, 32);

            PublicKey serverPublicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, clientPublicKeyRaw, KeyBlobFormat.RawPublicKey);

            // agree on shared secret
            SharedSecret sharedSecret = KeyAgreementAlgorithm.X25519.Agree(mainWindow.ClientKeyPair, serverPublicKey);

            if (sharedSecret == null)
            {
                connection.Close();
                return null;
            }

            return KeyDerivationAlgorithm.HkdfSha512.DeriveKey(sharedSecret, null, clientPublicKeyRaw, AeadAlgorithm.Aes256Gcm, CryptoUtils.AllowExport());
        }
    }

    internal class ClientDescriptor
    {
        private TcpClient tcpClient;
        private Thread clientThread;

        public ClientDescriptor(TcpClient tcpClient)
        {
            this.tcpClient = tcpClient;
        }

        public TcpClient TcpClient { get { return tcpClient; } }
    }
}
