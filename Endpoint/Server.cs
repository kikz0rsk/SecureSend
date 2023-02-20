using SecureSend.Protocol;
using NSec.Cryptography;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using SecureSend.Utils;
using SecureSend.Base;
using SecureSend.Exceptions;

namespace SecureSend.Endpoint
{
    public class Server : NetworkEndpoint
    {

        private int? port;
        public TcpListener? serverSocket;
        private Thread? thread;

        private volatile bool stopSignal = false;

        public Server(SecureSendApp application) : base(application)
        { }

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
            catch (SocketException)
            {
                serverSocket = new TcpListener(IPAddress.Any, 0);
                serverSocket.Start();
            }

            port = ((IPEndPoint)serverSocket.LocalEndpoint).Port;
            Application.Current.Dispatcher.Invoke(new Action(() =>
            {
                application.MainWindow.statusPortText.Content = "Port pre pripojenie: " + port.ToString();
            }));

            while (!stopSignal)
            {
                filesToSend.Clear();

                try
                {
                    // accepting loop
                    SetConnected(false);
                    connection = serverSocket.AcceptTcpClient();
                    SetConnected(true);
                    this.client = false;
                    stream = connection.GetStream();

                    HandleConnection();
                }
                catch (ThreadInterruptedException) { }
                catch (SocketException) { }
                catch (ConnectionClosedException) { }
                catch (IOException)
                {
                    MessageBox.Show("Spojenie zlyhalo.", "Chyba spojenia", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Vyskytla sa chyba: " + ex.ToString(), "Chyba", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        protected void HandleConnection()
        {
            Application.Current.Dispatcher.Invoke(new Action(() =>
            {
                application.MainWindow.currentConnectionText.Content = "Vytvára sa bezpečný kanál...";
            }));

            this.symmetricKey = EstablishTrust();
            if (this.symmetricKey == null)
            {
                Disconnect();
                Task.Run(() =>
                {
                    MessageBox.Show("Nepodarilo sa nadviazať spoločný šifrovací kľúč.", "Chyba pri pripájaní klienta",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                });
                return;
            }

            Application.Current.Dispatcher.Invoke(new Action(() =>
            {
                application.MainWindow.currentConnectionText.Content = "Čaká sa na potvrdenie užívateľa...";
            }));

            bool authorized = AuthorizeAccess();
            if (!authorized)
            {
                SendPacket(new NackPacket());
                Disconnect();
                return;
            }

            SendPacket(new AckPacket());

            try
            {
                Packet? packet = ReceivePacket();
                if (packet == null || packet.GetPacketType() != PacketType.ACK)
                {
                    throw new InvalidDataException();
                }
            }
            catch (Exception)
            {
                Disconnect();
                Task.Run(() =>
                {
                    MessageBox.Show("Užívateľ odmietol žiadosť o pripojenie.", "Spojenie bolo odmietnuté",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                });
                return;
            }

            if (application.PasswordAuthEnabled)
            {
                SendPacket(new PasswordAuthRequestPacket());

                try
                {
                    Packet? packet = ReceivePacket();
                    if (packet == null || packet.GetPacketType() != PacketType.PASSWORD_AUTH_RESP)
                    {
                        throw new InvalidDataException();
                    }

                    PasswordAuthResponsePacket pass = (PasswordAuthResponsePacket)packet;

                    // Prevent timing attacks, we do password hashing first
                    byte[] hash = HashAlgorithm.Sha512.Hash(
                            UTF8Encoding.UTF8.GetBytes(application.Password + pass.Salt));
                    bool correct = Enumerable.SequenceEqual(hash, pass.PasswordHash) &&
                        pass.Username.Equals(application.Username);

                    if (correct)
                    {
                        SendPacket(new AckPacket());
                    }
                    else
                    {
                        SendPacket(new NackPacket());
                        Disconnect();
                        return;
                    }
                }
                catch (Exception)
                {
                    return;
                }
            }
            else
            {
                SendPacket(new AckPacket());
            }

            SetConnected(true);
            CommunicationLoop();
        }

        protected override Key? EstablishTrust()
        {
            byte[] sessionId = new byte[64];
            CryptoUtils.FillWithRandomBytes(sessionId);

            ServerHandshake serverHandshake = new ServerHandshake(
                application.Key.PublicKey.Export(
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
            SharedSecret? sharedSecret = KeyAgreementAlgorithm.X25519.Agree(application.Key, remoteEndpointPublicKey);

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
