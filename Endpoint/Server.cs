using SecureSend.GUI;
using SecureSend.Protocol;
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
using SecureSend.Utils;
using SecureSend.Base;
using SecureSend.Exceptions;

namespace SecureSend.Endpoint
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
            Application.Current.Dispatcher.Invoke(new Action(() => {
                mainWindow.statusPortText.Content = "Port pre pripojenie: " + port.ToString(); }));

            while (!stopSignal)
            {
                try
                {
                    filesToSend.Clear();
                    // accepting loop
                    SetConnected(false);
                    connection = serverSocket.AcceptTcpClient();
                    SetConnected(true);
                    this.isClient = false;

                    Application.Current.Dispatcher.Invoke(new Action(() =>
                    {
                        mainWindow.currentConnectionText.Content = "Vytvára sa bezpečný kanál...";
                    }));

                    stream = connection.GetStream();

                    this.symmetricKey = EstablishTrust();
                    if (this.symmetricKey == null)
                    {
                        Disconnect();
                        Task.Run(() =>
                        {
                            MessageBox.Show("Nepodarilo sa nadviazať spoločný šifrovací kľúč.", "Chyba pri pripájaní klienta",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                        });
                        continue;
                    }

                    Application.Current.Dispatcher.Invoke(new Action(() =>
                    {
                        mainWindow.currentConnectionText.Content = "Čaká sa na potvrdenie užívateľa...";
                    }));

                    bool authorized = AuthorizeAccess();

                    if (!authorized)
                    {
                        SendPacket(new NackPacket());
                        Disconnect();
                        continue;
                    }

                    SendPacket(new AckPacket());

                    try
                    {
                        Packet? packet = ReceivePacket();
                        if (packet == null || packet.GetType() != PacketType.ACK)
                        {
                            throw new InvalidDataException();
                        }
                    }
                    catch (Exception ex)
                    {
                        Disconnect();
                        Task.Run(() =>
                        {
                            MessageBox.Show("Užívateľ odmietol žiadosť o pripojenie.", "Spojenie bolo odmietnuté",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                        });
                        continue;
                    }

                    if (SecureSendMain.Instance.PasswordAuthEnabled)
                    {
                        SendPacket(new PasswordAuthRequestPacket());

                        try
                        {
                            Packet? packet = ReceivePacket();
                            if (packet == null || packet.GetType() != PacketType.PASSWORD_AUTH_RESP)
                            {
                                throw new InvalidDataException();
                            }

                            PasswordAuthPacket pass = (PasswordAuthPacket)packet;

                            // Prevent timing attacks, we do password hashing first
                            byte[] hash = HashAlgorithm.Sha512.Hash(
                                    UTF8Encoding.UTF8.GetBytes(SecureSendMain.Instance.Password + pass.Salt));
                            bool correct = Enumerable.SequenceEqual(hash, pass.PasswordHash) &&
                                pass.Username.Equals(SecureSendMain.Instance.Username);

                            if (correct)
                            {
                                SendPacket(new AckPacket());
                            }
                            else
                            {
                                SendPacket(new NackPacket());
                                Disconnect();
                                continue;
                            }
                        }
                        catch (Exception ex)
                        {
                            continue;
                        }
                    }
                    else
                    {
                        SendPacket(new AckPacket());
                    }

                    SetConnected(true);
                    CommunicationLoop();

                }
                catch (ThreadInterruptedException inter)
                {
                    throw inter;
                }
                catch (SocketException ex) { }
                catch (ConnectionClosedException) { }
                catch (IOException ex)
                {
                    MessageBox.Show("Spojenie zlyhalo.", "Chyba spojenia", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Vyskytla sa chyba: " + ex.ToString(), "Chyba", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        

        protected override Key? EstablishTrust()
        {
            byte[] sessionId = new byte[64];
            CryptoUtils.FillWithRandomBytes(sessionId);

            ServerHandshake serverHandshake = new ServerHandshake(
                IdentityManager.Instance.GetKey().PublicKey.Export(
                    KeyBlobFormat.RawPublicKey), sessionId, TrustedEndpointsManager.GetDeviceFingerprint());

            SendUnencryptedPacket(serverHandshake);

            Packet? packet = ReceiveUnencryptedPacket();

            if (packet == null) return null;

            ClientHandshake clientHandshake;
            try
            {
                clientHandshake = (ClientHandshake)packet;
            }
            catch (InvalidCastException)
            {
                return null;
            }

            deviceFingerprint = clientHandshake.DeviceFingerprint;
            remoteEndpointPublicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, clientHandshake.PublicKey, KeyBlobFormat.RawPublicKey);

            // agree on shared secret
            SharedSecret? sharedSecret = KeyAgreementAlgorithm.X25519.Agree(IdentityManager.Instance.GetKey(), remoteEndpointPublicKey);

            if (sharedSecret == null)
            {
                return null;
            }

            CryptoUtils.FillWithRandomBytes(lastSequenceForNonce);

            return KeyDerivationAlgorithm.HkdfSha512.DeriveKey(sharedSecret, sessionId, null, AeadAlgorithm.Aes256Gcm, CryptoUtils.AllowExport());
        }

        public void StopServer()
        {
            Disconnect();
            stopSignal = true;
            serverSocket?.Stop();
        }

        public int? Port { get { return port; } }

        public Thread? ServerThread
        {
            get { return thread; }
        }
    }
}
