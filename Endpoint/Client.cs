﻿using SecureSend.GUI;
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

        public Thread? Thread { get; private set; }

        public Client(SecureSendApp application) : base(application)
        { }

        public void Connect(string ipAddress, string port)
        {
            this.ipAddress = ipAddress;
            this.port = port;

            Thread = new Thread(_Connect);
            Thread.IsBackground = true;
            Thread.Start();
        }

        protected void _Connect()
        {
            filesToSend.Clear();
            try
            {
                connection = new TcpClient();

                InvokeGUI(() =>
                {
                    application.MainWindow.currentConnectionText.Content = "Connecting...";
                    application.MainWindow.disconnectBtn.IsEnabled = false;
                    application.MainWindow.connectBtn.IsEnabled = false;
                });

                try
                {
                    connection.Connect(IPAddress.Parse(ipAddress), int.Parse(port));
                }
                catch (FormatException)
                {
                    MessageBox.Show("Incorrect input.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                catch (SocketException ex)
                {
                    MessageBox.Show("Error while connecting. Details: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
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
                MessageBox.Show("Unexpected response.", "Connection error", MessageBoxButton.OK, MessageBoxImage.Error);
                Debug.Write(ex.ToString());
            }
            catch (IOException)
            {
                MessageBox.Show("Connection failed.", "Connection error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (ObjectDisposedException)
            {
                MessageBox.Show("Connection failed.", "Connection error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show("An error occurred: " + ex.ToString(), "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                filesToSend.Clear();
                Disconnect();
                SetConnected(false);
                cipherAlgorithm = AeadAlgorithm.Aes256Gcm;
                lastRemoteNonce = null;
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

            try
            {
                Segment segment = ReceiveEncryptedSegment();

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

                    if(!window.ClosedWithConfirm)
                    {
                        Disconnect();
                        return;
                    }

                    byte[] hash = HashAlgorithm.Sha256.Hash(
                            UTF8Encoding.UTF8.GetBytes(window.Password + salt));

                    SendEncryptedSegment(
                        new PasswordAuthResponseSegment(window.Username, hash));

                    segment = ReceiveEncryptedSegment();
                    if (segment.Type == SegmentType.NACK)
                    {
                        Task.Run(() =>
                        {
                            MessageBox.Show("Incorrect username or password.", "Connection denied",
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
                    MessageBox.Show(ex.ToString(), "Connection denied",
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
                TrustedEndpointsManager.GetHardwareFingerprint(), System.Environment.MachineName);

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

            deviceFingerprint = serverHandshake.HardwareFingerprint;
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
    }
}
