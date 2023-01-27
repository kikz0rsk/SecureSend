using SecureSend.GUI;
using SecureSend.Protocol;
using NSec.Cryptography;
using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Packet = SecureSend.Protocol.Packet;
using SecureSend.Utils;
using SecureSend.Base;

namespace SecureSend.Endpoint
{
    internal class Client : NetworkEndpoint
    {
        private string? ipAddress;
        private string? port;
        protected Thread? thread;

        public Client(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
        }

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
                this.isClient = true;

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
                        MessageBox.Show("Nepodarilo sa nadviazať spoločný šifrovací kľúč.", "Chyba pri pripájaní k serveru",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                    return;
                }

                Application.Current.Dispatcher.Invoke(new Action(() =>
                {
                    mainWindow.currentConnectionText.Content = "Čaká sa na potvrdenie užívateľa...";
                }));

                if (!TrustedEndpointsManager.Instance.Lookup(deviceFingerprint, remoteEndpointPublicKey.Export(KeyBlobFormat.RawPublicKey)))
                {
                    IPEndPoint endpoint = connection.Client.RemoteEndPoint as IPEndPoint;
                    AcceptConnectionResult result = Application.Current.Dispatcher.Invoke(() =>
                    {
                        AcceptConnection acceptConnection = new AcceptConnection(
                            true, endpoint.Address.ToString(), deviceFingerprint, remoteEndpointPublicKey.Export(KeyBlobFormat.RawPublicKey));
                        acceptConnection.Owner = SecureSendMain.Instance.MainWindow;
                        acceptConnection.ShowDialog();
                        return acceptConnection.Result;
                    });

                    if (result == AcceptConnectionResult.Reject)
                    {
                        Disconnect();
                        return;
                    }

                    if (result == AcceptConnectionResult.AcceptAndRemember)
                    {
                        TrustedEndpointsManager.Instance.Add(deviceFingerprint, remoteEndpointPublicKey.Export(KeyBlobFormat.RawPublicKey));
                    }
                }

                SendPacket(new AckPacket());

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
                    return;
                }

                SetConnected(true);
                CommunicationLoop();
            }
            catch (ThreadInterruptedException inter)
            {

            }
            finally
            {
                filesToSend.Clear();
                connection?.Close();
                SetConnected(false);
            }
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

            return KeyDerivationAlgorithm.HkdfSha512.DeriveKey(sharedSecret,
                serverHandshake.SessionId, null, AeadAlgorithm.Aes256Gcm, CryptoUtils.AllowExport());
        }

        public Thread? GetThread()
        {
            return thread;
        }
    }
}
