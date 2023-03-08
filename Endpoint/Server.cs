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
using Open.Nat;
using System.Diagnostics;

namespace SecureSend.Endpoint
{
    public class Server : NetworkEndpoint
    {

        private int? port;
        public TcpListener? serverSocket;
        private Thread? thread;

        private volatile bool stopSignal = false;

        private volatile NatDevice? natDevice;
        private volatile Mapping? mapping;

        public Server(SecureSendApp application) : base(application)
        { }

        public void StartServer()
        {
            if (thread != null) return;

            thread = new Thread(_StartServer);
            thread.IsBackground = true;
            thread.Start();
        }

        protected void _StartServer()
        {
            try
            {
                serverSocket = new TcpListener(IPAddress.Any, application.ServerPort);
                serverSocket.Start();
            }
            catch (SocketException)
            {
                serverSocket = new TcpListener(IPAddress.Any, 0);
                serverSocket.Start();
            }

            port = ((IPEndPoint)serverSocket.LocalEndpoint).Port;
            InvokeGUI(() =>
            {
                application.MainWindow.statusPortText.Content = "Port pre pripojenie: " + port.ToString();
            });

            while (!stopSignal)
            {
                try
                {
                    // accepting loop
                    connection = serverSocket.AcceptTcpClient();
                    SetConnected(true);
                    this.client = false;
                    stream = connection.GetStream();

                    HandleConnection();
                }
                catch (ThreadInterruptedException) { }
                catch (SocketException) { }
                catch (ConnectionClosedException) { }
                catch (ArgumentOutOfRangeException ex)
                {
                    MessageBox.Show("Neočakávaná odpoveď.", "Chyba spojenia", MessageBoxButton.OK, MessageBoxImage.Error);
                    Debug.Write(ex.ToString());
                }
                catch (IOException)
                {
                    MessageBox.Show("Spojenie zlyhalo.", "Chyba spojenia", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch (ObjectDisposedException)
                {
                    MessageBox.Show("Spojenie zlyhalo.", "Chyba spojenia", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Vyskytla sa chyba: " + ex.ToString(), "Chyba", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                finally
                {
                    filesToSend.Clear();
                    SetConnected(false);
                    cipherAlgorithm = AeadAlgorithm.Aes256Gcm;
                }
            }
        }

        protected void HandleConnection()
        {
            InvokeGUI(() =>
            {
                application.MainWindow.currentConnectionText.Content = "Vytvára sa bezpečný kanál...";
            });

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

            InvokeGUI(() =>
            {
                application.MainWindow.currentConnectionText.Content = "Čaká sa na potvrdenie užívateľa...";
            });

            bool authorized = AuthorizeAccess();
            if (!authorized)
            {
                SendEncryptedSegment(new NackSegment());
                Disconnect();
                return;
            }

            SendEncryptedSegment(new AckSegment());

            try
            {
                Segment segment = ReceiveEncryptedSegment();
                if (segment.Type != SegmentType.ACK)
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
                string salt = CryptoUtils.CreateRandomString(16);
                SendEncryptedSegment(
                    new PasswordAuthRequestSegment(salt));

                InvokeGUI(() =>
                {
                    application.MainWindow.currentConnectionText.Content = "Čaká sa na zadanie mena a hesla...";
                });

                try
                {
                    Segment segment = ReceiveEncryptedSegment();
                    if (segment.Type != SegmentType.PASSWORD_AUTH_RESP)
                    {
                        throw new InvalidDataException();
                    }

                    PasswordAuthResponseSegment pass = (PasswordAuthResponseSegment)segment;

                    // Prevent timing attacks, we do password hashing first
                    byte[] hash = HashAlgorithm.Sha256.Hash(
                            UTF8Encoding.UTF8.GetBytes(application.Password + salt));
                    bool correct = Enumerable.SequenceEqual(hash, pass.PasswordHash) &&
                        pass.Username.Equals(application.Username);

                    if (correct)
                    {
                        SendEncryptedSegment(new AckSegment());
                    }
                    else
                    {
                        SendEncryptedSegment(new NackSegment());
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
                SendEncryptedSegment(new AckSegment());
            }

            SetConnected(true);
            CommunicationLoop();
        }

        protected override Key? EstablishTrust()
        {
            sessionId = new byte[64];
            CryptoUtils.FillWithRandomBytes(sessionId);

            ServerHandshake serverHandshake = new ServerHandshake(
                application.Key.PublicKey.Export(KeyBlobFormat.RawPublicKey), sessionId,
                TrustedEndpointsManager.GetHardwareFingerprint(), System.Environment.MachineName);

            SendUnencryptedSegment(serverHandshake);

            Segment? segment = ReceiveUnencryptedSegment();

            if (segment == null) return null;

            ClientHandshake clientHandshake;
            try
            {
                clientHandshake = (ClientHandshake)segment;
            }
            catch (InvalidCastException)
            {
                return null;
            }

            deviceFingerprint = clientHandshake.HardwareFingerprint;
            remoteEndpointPublicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, clientHandshake.PublicKey, KeyBlobFormat.RawPublicKey);
            remoteComputerName = clientHandshake.ComputerName;

            // agree on shared secret
            sharedSecret = KeyAgreementAlgorithm.X25519.Agree(application.Key, remoteEndpointPublicKey);
            if (sharedSecret == null)
            {
                return null;
            }

            CryptoUtils.FillWithRandomBytes(lastSequenceForNonce);

            return KeyDerivationAlgorithm.HkdfSha512.DeriveKey(sharedSecret, sessionId, null, AeadAlgorithm.Aes256Gcm, CryptoUtils.AllowExport());
        }

        public void StopServer()
        {
            if (serverSocket == null || !serverSocket.Server.IsBound) return;

            Disconnect();
            stopSignal = true;
            serverSocket?.Stop();

            InvokeGUI(() =>
            {
                application.MainWindow.statusPortText.Content = "Pripájanie je vypnuté";
            });
        }

        public async void EnableUpnpForward()
        {
            if (this.port == null) return;
            if (this.mapping != null) return;

            InvokeGUI(() => application.MainWindow.upnpPortStatus.Content = "Prebieha pokus o presmerovanie portu...");
            try
            {
                var discoverService = new NatDiscoverer();
                var cts = new CancellationTokenSource(10000);
                this.natDevice = await discoverService.DiscoverDeviceAsync(PortMapper.Upnp, cts);

                int attempt = 1;
                int publicPort = 23488;
                bool success = false;
                while (attempt < 10)
                {
                    try
                    {
                        Mapping mapping = new Mapping(Open.Nat.Protocol.Tcp, (int)port, publicPort, "SecureSend");
                        await natDevice.CreatePortMapAsync(mapping);
                        success = true;
                        this.mapping = mapping;
                        break;
                    }
                    catch (MappingException ex)
                    {
                        Debug.WriteLine("[NAT] mapping conflict: " + ex.ToString());
                        publicPort = (CryptoUtils.GetRandomInstance().Next()) % (65_535 - 5_000) + 5_000;
                        Debug.WriteLine("[NAT] trying random port");
                        attempt++;
                    }
                    catch (Exception)
                    { break; }
                }

                if (success)
                {
                    InvokeGUI(() =>
                    {
                        application.MainWindow.upnpPortStatus.Content = "Port pre pripojenie z internetu: " + publicPort.ToString();
                    });
                    Debug.WriteLine("[NAT] successfully setup UPnP port forward");
                    return;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[NAT] general exception: " + ex.ToString());
            }

            InvokeGUI(() =>
            {
                application.MainWindow.upnpPortStatus.Content = "Presmerovanie portu UPnP bolo neúspešné";
            });
        }

        public async void DisableUpnpForward()
        {
            if (natDevice == null || mapping == null) return;

            await natDevice?.DeletePortMapAsync(mapping);
            this.mapping = null;

            InvokeGUI(() =>
            {
                application.MainWindow.upnpPortStatus.Content = "";
            });
        }

        public int? Port { get { return port; } }

        public Thread? ServerThread
        {
            get { return thread; }
        }
    }
}
