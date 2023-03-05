using SecureSend.GUI;
using SecureSend.Protocol;
using NSec.Cryptography;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using SecureSend.Utils;
using SecureSend.Base;
using System.Text;
using SecureSend.Exceptions;
using System.Diagnostics;

namespace SecureSend.Endpoint
{
    public class Client : NetworkEndpoint
    {
        private string? ipAddress;
        private string? port;
        protected Thread? thread;

        public Client(SecureSendApp application) : base(application)
        { }

        public void Connect(string ipAddress, string port)
        {
            this.ipAddress = ipAddress;
            this.port = port;

            thread = new Thread(_Connect);
            thread.IsBackground = true;
            thread.Start();
        }

        protected void _Connect()
        {
            filesToSend.Clear();
            try
            {
                connection = new TcpClient();

                InvokeGUI(new Action(() =>
                {
                    application.MainWindow.currentConnectionText.Content = "Prebieha pripájanie...";
                    application.MainWindow.disconnectBtn.IsEnabled = false;
                    application.MainWindow.connectBtn.IsEnabled = false;
                }));

                try
                {
                    connection.Connect(IPAddress.Parse(ipAddress), int.Parse(port));
                }
                catch (FormatException)
                {
                    MessageBox.Show("Nesprávne zadané parametre.", "Chyba", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                catch (SocketException ex)
                {
                    MessageBox.Show("Chyba pri pripájaní. Podrobnosti: " + ex.Message, "Chyba", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                finally
                {
                    if (!connection.Connected)
                    {
                        SetConnected(false);
                    }
                }

                SetConnected(true);
                this.client = true;
                stream = connection.GetStream();

                HandleConnection();
            }
            catch (ThreadInterruptedException)
            { }
            catch (ConnectionClosedException)
            { }
            catch (SocketException)
            { }
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
                Disconnect();
                SetConnected(false);
                cipherAlgorithm = AeadAlgorithm.Aes256Gcm;
            }
        }

        protected void HandleConnection()
        {
            InvokeGUI(new Action(() =>
            {
                application.MainWindow.currentConnectionText.Content = "Vytvára sa bezpečný kanál...";
            }));

            this.symmetricKey = EstablishTrust();
            if (this.symmetricKey == null)
            {
                Disconnect();
                Task.Run(() =>
                {
                    MessageBox.Show("Nepodarilo sa nadviazať spoločný šifrovací kľúč.", "Chyba pri pripájaní k serveru",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                });
                return;
            }

            InvokeGUI(new Action(() =>
            {
                application.MainWindow.currentConnectionText.Content = "Čaká sa na potvrdenie užívateľa...";
            }));

            bool authorized = AuthorizeAccess(true);
            if (!authorized)
            {
                SendEncryptedSegment(new NackSegment());
                Disconnect();
                return;
            }

            SendEncryptedSegment(new AckSegment());

            try
            {
                Segment segment = ReceiveSegment();
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

            try
            {
                Segment segment = ReceiveSegment();

                if (segment.Type == SegmentType.PASSWORD_AUTH_REQ)
                {
                    string salt = ((PasswordAuthRequestSegment)segment).Salt;
                    PasswordAuthWindow window = Application.Current.Dispatcher.Invoke(() =>
                    {
                        PasswordAuthWindow window = new PasswordAuthWindow(false, null);
                        window.Owner = application.MainWindow;
                        window.ShowDialog();
                        return window;
                    });

                    byte[] hash = HashAlgorithm.Sha256.Hash(
                            UTF8Encoding.UTF8.GetBytes(window.Password + salt));

                    SendEncryptedSegment(
                        new PasswordAuthResponseSegment(window.Username, hash));

                    segment = ReceiveSegment();
                    if (segment.Type == SegmentType.NACK)
                    {
                        Task.Run(() =>
                        {
                            MessageBox.Show("Nesprávne meno alebo heslo.", "Spojenie bolo odmietnuté",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                        });
                        Disconnect();
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                Task.Run(() =>
                {
                    MessageBox.Show(ex.ToString(), "Spojenie bolo odmietnuté",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                });
                return;
            }

            SetConnected(true);
            CommunicationLoop();
        }

        protected override Key? EstablishTrust()
        {
            ClientHandshake clientHandshake = new ClientHandshake(
                IdentityManager.Instance.GetKey().PublicKey.Export(KeyBlobFormat.RawPublicKey),
                TrustedEndpointsManager.GetDeviceFingerprint(), System.Environment.MachineName);

            SendUnencryptedSegment(clientHandshake);

            Segment? segment = ReceiveUnencryptedSegment();

            if (segment == null) return null;

            ServerHandshake serverHandshake;
            try
            {
                serverHandshake = (ServerHandshake)segment;
            }
            catch (InvalidCastException)
            {
                return null;
            }

            deviceFingerprint = serverHandshake.DeviceFingerprint;
            remoteEndpointPublicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, serverHandshake.PublicKey, KeyBlobFormat.RawPublicKey);
            remoteComputerName = serverHandshake.ComputerName;

            // agree on shared secret
            sharedSecret = KeyAgreementAlgorithm.X25519.Agree(IdentityManager.Instance.GetKey(), remoteEndpointPublicKey);
            if (sharedSecret == null)
            {
                return null;
            }

            CryptoUtils.FillWithRandomBytes(lastSequenceForNonce);

            sessionId = serverHandshake.SessionId;
            return KeyDerivationAlgorithm.HkdfSha512.DeriveKey(sharedSecret,
                serverHandshake.SessionId, null, AeadAlgorithm.Aes256Gcm, CryptoUtils.AllowExport());
        }

        public Thread? GetThread()
        {
            return thread;
        }
    }
}
