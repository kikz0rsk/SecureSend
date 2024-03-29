﻿using SecureSend.Protocol;
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

        private volatile int port;
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
                application.MainWindow.statusPortText.Content = "Port for incoming connections: " + port.ToString();
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
                    MessageBox.Show("Unexpected response.", "Protocol error", MessageBoxButton.OK, MessageBoxImage.Error);
                    Debug.Write(ex.ToString());
                }
                catch (IOException)
                {
                    MessageBox.Show("Connection failed.", "Connection error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch (ObjectDisposedException)
                {
                    MessageBox.Show("Connection failed.", "Chyba spojenia", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("An error occurred: " + ex.ToString(), "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                finally
                {
                    filesToSend.Clear();
                    SetConnected(false);
                    cipherAlgorithm = AeadAlgorithm.Aes256Gcm;
                    lastRemoteNonce = null;
                }
            }
        }

        protected void HandleConnection()
        {
            InvokeGUI(() =>
            {
                application.MainWindow.currentConnectionText.Content = "Establishing secure channel...";
            });

            this.symmetricKey = EstablishTrust();
            if (this.symmetricKey == null)
            {
                Disconnect();
                Task.Run(() =>
                {
                    MessageBox.Show("Could not negotiate shared encryption key.", "Key error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                });
                return;
            }

            InvokeGUI(() =>
            {
                application.MainWindow.currentConnectionText.Content = "Waiting for connection authorization...";
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
                    MessageBox.Show("User denied connection request.", "Connection denied",
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
                    application.MainWindow.currentConnectionText.Content = "Waiting for username and password authentication...";
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
                application.MainWindow.statusPortText.Content = "Incoming connections are disabled";
            });
        }

        public async Task EnableUpnpForward()
        {
            if (this.mapping != null) return;

            InvokeGUI(() => application.MainWindow.upnpPortStatus.Content = "[UPnP] Trying automatic port forward...");
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
                        Debug.WriteLine("[UPnP] mapping conflict: " + ex.ToString());
                        publicPort = (CryptoUtils.GetRandomInstance().Next()) % (65_535 - 5_000) + 5_000;
                        Debug.WriteLine("[UPnP] trying random port");
                        attempt++;
                    }
                    catch (Exception)
                    { break; }
                }

                if (success)
                {
                    InvokeGUI(() =>
                    {
                        application.MainWindow.upnpPortStatus.Content = "Port for connections from the Internet: " + publicPort.ToString();
                    });
                    Debug.WriteLine("[UPnP] successfully setup port forward");
                    return;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[UPnP] general exception: " + ex.ToString());
            }

            InvokeGUI(() =>
            {
                application.MainWindow.upnpPortStatus.Content = "[UPnP] Port forward failed";
            });
        }

        public async Task DisableUpnpForward()
        {
            if (natDevice == null || mapping == null) return;

            try
            {
                await natDevice?.DeletePortMapAsync(mapping);

                this.mapping = null;

                InvokeGUI(() =>
                {
                    application.MainWindow.upnpPortStatus.Content = "";
                });
            } catch(Exception ex) {
                Debug.WriteLine("[UPnP] Exception while disabling: " + ex.ToString());
            }
        }

        public int? Port { get { return port; } }
    }
}
