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
using Packet = SecureSend.Protocol.Packet;
using SecureSend.Utils;
using SecureSend.Base;
using System.Text;
using SecureSend.Exceptions;

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
            thread.Start();
        }

        protected void _Connect()
        {
            filesToSend.Clear();
            try
            {
                connection = new TcpClient();
                try
                {
                    connection.Connect(IPAddress.Parse(ipAddress), int.Parse(port));
                }
                catch (FormatException)
                {
                    MessageBox.Show("Nesprávne zadané parametre.", "Chyba", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                } catch(SocketException ex)
                {
                    MessageBox.Show("Chyba pri pripájaní. Podrobnosti: " + ex.ToString(), "Chyba", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                SetConnected(true);
                this.client = true;
                stream = connection.GetStream();

                HandleConnection();
            }
            catch (ThreadInterruptedException inter)
            { }
            catch (ConnectionClosedException)
            { }
            catch(IOException ex)
            {
                MessageBox.Show("Spojenie zlyhalo.", "Chyba spojenia", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch(Exception ex)
            {
                MessageBox.Show("Vyskytla sa chyba: " + ex.ToString(), "Chyba", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                filesToSend.Clear();
                Disconnect();
                SetConnected(false);
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
                    MessageBox.Show("Nepodarilo sa nadviazať spoločný šifrovací kľúč.", "Chyba pri pripájaní k serveru",
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
                return;
            }

            try
            {
                Packet? packet = ReceivePacket();
                if (packet == null)
                {
                    throw new InvalidDataException();
                }

                if (packet.GetType() == PacketType.PASSWORD_AUTH_REQ)
                {
                    PasswordAuthWindow window = Application.Current.Dispatcher.Invoke(() =>
                    {
                        PasswordAuthWindow window = new PasswordAuthWindow(false, null);
                        window.Owner = application.MainWindow;
                        window.ShowDialog();
                        return window;
                    });

                    string salt = CryptoUtils.CreateSalt(16);
                    byte[] hash = HashAlgorithm.Sha512.Hash(
                            UTF8Encoding.UTF8.GetBytes(window.Password + salt));

                    PasswordAuthPacket authPacket = new PasswordAuthPacket(window.Username, hash, salt);
                    SendPacket(authPacket);

                    packet = ReceivePacket();
                    if (packet.GetType() == PacketType.NACK)
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
                IdentityManager.Instance.GetKey().PublicKey.Export(
                    KeyBlobFormat.RawPublicKey), 0, TrustedEndpointsManager.GetDeviceFingerprint());

            SendUnencryptedPacket(clientHandshake);

            Packet? packet = ReceiveUnencryptedPacket();

            if (packet == null) return null;

            ServerHandshake serverHandshake;
            try
            {
                serverHandshake = (ServerHandshake)packet;
            }
            catch (InvalidCastException)
            {
                return null;
            }

            deviceFingerprint = serverHandshake.DeviceFingerprint;
            remoteEndpointPublicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, serverHandshake.PublicKey, KeyBlobFormat.RawPublicKey);

            // agree on shared secret
            SharedSecret? sharedSecret = KeyAgreementAlgorithm.X25519.Agree(IdentityManager.Instance.GetKey(), remoteEndpointPublicKey);

            if (sharedSecret == null)
            {
                return null;
            }

            CryptoUtils.FillWithRandomBytes(lastSequenceForNonce);

            return KeyDerivationAlgorithm.HkdfSha512.DeriveKey(sharedSecret,
                serverHandshake.SessionId, null, AeadAlgorithm.Aes256Gcm, CryptoUtils.AllowExport());
        }

        public Thread? GetThread()
        {
            return thread;
        }
    }
}
