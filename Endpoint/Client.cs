using BP.GUI;
using BP.Protocol;
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
using Packet = BP.Protocol.Packet;

namespace BP.Endpoint
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
                connection.Connect(IPAddress.Parse(ipAddress), int.Parse(port));

                SetConnected(true);
                Application.Current.Dispatcher.Invoke(new Action(() => {
                    mainWindow.currentConnectionText.Content = "Vytvára sa bezpečný kanál...";
                }));
                this.isClient = true;

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

                Application.Current.Dispatcher.Invoke(new Action(() => {
                    mainWindow.currentConnectionText.Content = "Čaká sa na potvrdenie užívateľa..."; }));

                IPEndPoint endpoint = connection.Client.RemoteEndPoint as IPEndPoint;
                AcceptConnectionResult result = Application.Current.Dispatcher.Invoke(() => {
                    AcceptConnection acceptConnection = new AcceptConnection(true,
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
                    return;
                }

                try
                {
                    Packet? packet = ReceivePacket();
                    if (packet == null || packet.GetType() != Packet.Type.ACK)
                    {
                        throw new InvalidDataException();
                    }
                } catch(Exception ex)
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
                
            } finally
            {
                filesToSend.Clear();
                connection?.Close();
                SetConnected(false);
            }
        }

        protected override Key? EstablishTrust()
        {

            ClientHandshake clientHandshake = new ClientHandshake(
                mainWindow.ClientKeyPair.PublicKey.Export(KeyBlobFormat.RawPublicKey), 0);

            SendUnencryptedPacket(clientHandshake);

            Packet? packet = ReceiveUnencryptedPacket();

            if (packet == null) return null;

            ServerHandshake serverHandshake;
            try
            {
                serverHandshake = (ServerHandshake)packet;
            } catch(InvalidCastException)
            {
                return null;
            }

            remoteEndpointPublicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, serverHandshake.PublicKey, KeyBlobFormat.RawPublicKey);

            // agree on shared secret
            SharedSecret? sharedSecret = KeyAgreementAlgorithm.X25519.Agree(mainWindow.ClientKeyPair, remoteEndpointPublicKey);

            if (sharedSecret == null)
            {
                return null;
            }

            return KeyDerivationAlgorithm.HkdfSha512.DeriveKey(sharedSecret, serverHandshake.SessionId, null, AeadAlgorithm.Aes256Gcm, CryptoUtils.AllowExport());
        }

        public Thread? GetThread()
        {
            return thread;
        }
    }
}
