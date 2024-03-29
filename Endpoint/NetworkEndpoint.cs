﻿using NSec.Cryptography;
using SecureSend.Base;
using SecureSend.GUI;
using SecureSend.Protocol;
using SecureSend.Utils;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace SecureSend.Endpoint
{
    public abstract class NetworkEndpoint
    {
        protected Key? symmetricKey;
        protected PublicKey remoteEndpointPublicKey;
        protected byte[] deviceFingerprint;
        protected string? remoteComputerName;
        protected volatile byte[]? sessionId;
        protected volatile SharedSecret? sharedSecret;

        protected NetworkStream? stream;
        protected TcpClient? connection;

        protected ConcurrentQueue<string> filesToSend = new ConcurrentQueue<string>();

        protected SecureSendApp application;

        protected volatile bool connected = false;
        protected volatile bool client = false;
        protected byte[] lastSequenceForNonce = new byte[6];
        protected byte[]? lastRemoteNonce = new byte[12];

        protected volatile AeadAlgorithm cipherAlgorithm = AeadAlgorithm.Aes256Gcm;

        public NetworkEndpoint(SecureSendApp application)
        {
            this.application = application;
        }

        protected void SendUnencryptedSegment(Segment segment)
        {
            byte[] serializedSegment = segment.BuildSegment();

            byte[] bytesToSend = Segment.EncodeUShort(Convert.ToUInt16(serializedSegment.Length)).Concat(serializedSegment).ToArray();
            stream.Write(bytesToSend, 0, bytesToSend.Length);
        }

        protected Segment? ReceiveUnencryptedSegment()
        {
            ushort segmentLength = Segment.DecodeUShort(NetworkUtils.ReadExactlyBytes(stream, 2));
            byte[] segmentBytes = NetworkUtils.ReadExactlyBytes(stream, segmentLength);

            Segment? segment = Segment.Deserialize(segmentBytes);

            return segment;
        }

        protected void SendEncryptedSegment(Segment segment)
        {
            byte[] serializedSegment = segment.BuildSegment();

            byte[] nonceRandom = new byte[6];
            CryptoUtils.FillWithRandomBytes(nonceRandom);

            byte[] nonce = nonceRandom.Concat(lastSequenceForNonce).ToArray();
            IncrementNonce();

            byte[]? encryptedPayload = cipherAlgorithm.Encrypt(symmetricKey, nonce, null, serializedSegment);


            byte[] segmentLengthBytes = Segment.EncodeUShort(Convert.ToUInt16(encryptedPayload.Length + 12)); // Nonce is 12 bytes
            byte[] bytesToSend = segmentLengthBytes.Concat(nonce).Concat(encryptedPayload).ToArray();
            stream.Write(bytesToSend, 0, bytesToSend.Length);
        }

        protected Segment ReceiveEncryptedSegment()
        {
            while (true)
            {
                ushort segmentLength = Segment.DecodeUShort(NetworkUtils.ReadExactlyBytes(stream, 2));

                ReadOnlySpan<byte> encryptedSegment = NetworkUtils.ReadExactlyBytes(stream, segmentLength);

                byte[] nonce = encryptedSegment.Slice(0, 12).ToArray();
                ReadOnlySpan<byte> payload = encryptedSegment.Slice(12);
                byte[]? decryptedSegmentBytes = cipherAlgorithm.Decrypt(symmetricKey, nonce, null, payload);

                if (lastRemoteNonce != null)
                {
                    if (nonce.SequenceEqual(lastRemoteNonce)) continue; // Nonce definitively should not be the same as the previous one

                    ulong lastNonceUint64 = NonceToUint64(lastRemoteNonce.Skip(6).Take(6).ToArray());
                    ulong thisNonceUint64 = NonceToUint64(nonce.Skip(6).Take(6).ToArray());

                    if (lastNonceUint64 != ulong.MaxValue &&
                        thisNonceUint64 <= lastNonceUint64)
                    {
                        Debug.WriteLine("Bad nonce. Last=" + lastNonceUint64 + " This=" + thisNonceUint64);
                        continue;
                    }
                }

                if (decryptedSegmentBytes == null)
                {
                    Debug.WriteLine("Failed to decrypt incoming message");
                    continue;
                }

                Segment? segment = Segment.Deserialize(decryptedSegmentBytes);

                if (segment == null)
                {
                    Debug.WriteLine("Failed to deserialize incoming message");
                    continue;
                }

                lastRemoteNonce = nonce;

                return segment;
            }
        }

        protected abstract Key? EstablishTrust();

        protected void _ChangeCipher(CipherAlgorithm algo, byte[] salt)
        {
            Key? key = null;
            AeadAlgorithm newAlgo;
            switch (algo)
            {
                case CipherAlgorithm.ChaCha20Poly1305:
                    newAlgo = AeadAlgorithm.ChaCha20Poly1305;
                    key = KeyDerivationAlgorithm.HkdfSha512.DeriveKey(
                        sharedSecret, salt, null, AeadAlgorithm.ChaCha20Poly1305, CryptoUtils.AllowExport());
                    break;
                default:
                    newAlgo = AeadAlgorithm.Aes256Gcm;
                    key = KeyDerivationAlgorithm.HkdfSha512.DeriveKey(
                        sharedSecret, salt, null, AeadAlgorithm.Aes256Gcm, CryptoUtils.AllowExport());
                    break;
            }

            if (key == null)
            {
                Disconnect();
                Debug.WriteLine("[change cipher] failed");
                return;
            }

            this.sessionId = salt;
            this.symmetricKey = key;
            this.cipherAlgorithm = newAlgo;

            InvokeGUI(() => application.MainWindow.SetCipher(algo));
        }

        public void ChangeCipher(CipherAlgorithm algo, byte[] salt)
        {
            SendEncryptedSegment(new CipherChangeSegment(algo, salt));

            _ChangeCipher(algo, salt);
        }

        protected void ReceiveFile()
        {
            InvokeGUI(() =>
            {
                application.MainWindow.fileProgressBar.IsIndeterminate = true;
                application.MainWindow.sendFileButton.IsEnabled = false;
                application.MainWindow.statusText.Content = "Odosielacie zariadenie začína prenos";
                application.MainWindow.currentConnectionText.Content = "Prijímanie súboru...";
                application.MainWindow.DisableCipherChange();
            });

            Segment segment = ReceiveEncryptedSegment();

            FileInfoSegment fileInfo = (FileInfoSegment)segment;

            InvokeGUI(() =>
            {
                application.MainWindow.statusText.Content = "Prichádzajúci súbor " + fileInfo.FileName;
                application.MainWindow.fileProgressBar.Value = 0;
                application.MainWindow.sendFileButton.IsEnabled = false;
                application.MainWindow.fileProgressBar.IsIndeterminate = false;
            });

            ulong totalBytes = fileInfo.FileSize;

            string saveFolder = Application.Current.Dispatcher.Invoke(() =>
            {
                return application.MainWindow.saveFolderLocation.Text.Trim();
            });

            if (!Directory.Exists(saveFolder))
            {
                try
                {
                    Directory.CreateDirectory(saveFolder);
                }
                catch (Exception)
                {
                    saveFolder = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads\\SecureSend";
                    Task.Run(() =>
                    {
                        MessageBox.Show("Nepodarilo sa vytvoriť zadaný adresár na uloženie súboru. Súbor sa uloží na prednastavené umiestnenie: " + saveFolder, "Chyba pri vytváraní adresára",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                    });
                }
            }

            string freeFileName = GenerateFreeFileName(saveFolder, fileInfo.FileName);
            string savePath = Path.Combine(saveFolder, freeFileName);

            connection.ReceiveTimeout = 30_000;
            using (FileStream fileStream = new FileStream(savePath, FileMode.Create))
            {
                ulong bytesWritten = 0;
                while (bytesWritten < totalBytes)
                {
                    Segment dataSegment = ReceiveEncryptedSegment();

                    if (dataSegment.Type != SegmentType.DATA)
                    {
                        continue;
                    }

                    byte[] data = ((DataSegment)dataSegment).Data;

                    fileStream.Write(data);
                    bytesWritten += (ulong)data.Length;
                    InvokeAsyncGUI(() =>
                    {
                        application.MainWindow.SetProgress(bytesWritten, totalBytes);
                    });
                }
            }
            connection.ReceiveTimeout = 0;

            InvokeGUI(() =>
            {
                application.MainWindow.statusText.Content = "Overuje sa kontrolný súčet súboru...";
                application.MainWindow.fileProgressBar.IsIndeterminate = true;
            });

            try
            {
                byte[] hash = CryptoUtils.CalculateFileHash(savePath);

                bool isValid = Enumerable.SequenceEqual(fileInfo.Hash, hash);
                if (isValid)
                {
                    SendEncryptedSegment(new AckSegment());
                    Task.Run(() =>
                    {
                        MessageBox.Show("Súbor bol úspešne prijatý a uložený v ceste " + savePath, "Súbor prijatý", MessageBoxButton.OK, MessageBoxImage.Information);
                    });
                }
                else
                {
                    SendEncryptedSegment(new NackSegment());
                    Task.Run(() =>
                    {
                        MessageBox.Show("Kontrolný súčet sa nezhoduje! Súbor je pravdepodobne poškodený. Zopakujte prenos.", "Súbor je poškodený",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
            catch (Exception ex)
            {
                Task.Run(() =>
                {
                    MessageBox.Show("Integritu súboru sa nepodarilo overiť: " + ex.ToString(), "Chyba pri overovaní súboru",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                });
            }

            InvokeAsyncGUI(() =>
            {
                application.MainWindow.SetProgress(0, 1);
                application.MainWindow.statusText.Content = "Súbor bol prijatý";
                application.MainWindow.sendFileButton.IsEnabled = true;
                application.MainWindow.fileProgressBar.IsIndeterminate = false;
                application.MainWindow.currentConnectionText.Content = "Pripojené";
                application.MainWindow.EnableCipherChange();
            });
        }

        protected void SendFile()
        {
            string? filePathString;
            if (!filesToSend.TryDequeue(out filePathString))
            {
                return;
            }

            if (filePathString == null || !File.Exists(filePathString)) return;

            InvokeGUI(() =>
            {
                application.MainWindow.fileProgressBar.Value = 0;
                application.MainWindow.fileProgressBar.IsIndeterminate = true;
                application.MainWindow.sendFileButton.IsEnabled = false;
                application.MainWindow.statusText.Content = "Počíta sa kontrolný súčet súboru...";
                application.MainWindow.currentConnectionText.Content = "Odosielanie súboru...";
                application.MainWindow.DisableCipherChange();
            });

            SendEncryptedSegment(new PrepareTransferSegment());

            ulong totalBytes = (ulong)new FileInfo(filePathString).Length;

            byte[] hash = CryptoUtils.CalculateFileHash(filePathString);

            InvokeGUI(() =>
            {
                application.MainWindow.fileProgressBar.IsIndeterminate = false;
                application.MainWindow.statusText.Content = "Odosiela sa súbor...";
            });

            FileInfoSegment fileInfoSegment = new FileInfoSegment(Path.GetFileName(filePathString), totalBytes, hash);
            SendEncryptedSegment(fileInfoSegment);

            ulong bytesSent = 0;
            using (Stream fileStream = File.OpenRead(filePathString))
            {
                byte[] buffer = new byte[40_000];
                int bytesRead;
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    DataSegment data = new DataSegment(buffer.Take(bytesRead).ToArray());
                    SendEncryptedSegment(data);
                    bytesSent += (ulong)bytesRead;
                    InvokeAsyncGUI(() =>
                    {
                        application.MainWindow.SetProgress(bytesSent, totalBytes);
                    });
                }
            }

            InvokeAsyncGUI(() =>
            {
                application.MainWindow.statusText.Content = "Prijímajúce zariadenie overuje integritu súboru...";
                application.MainWindow.fileProgressBar.IsIndeterminate = true;
            });

            Segment result = ReceiveEncryptedSegment();

            if (result.Type == SegmentType.ACK)
            {
                Task.Run(() =>
                {
                    MessageBox.Show("Súbor " + fileInfoSegment.FileName + " bol úspešne odoslaný",
                        "Súbor odoslaný", MessageBoxButton.OK, MessageBoxImage.Information);
                });
            }
            else
            {
                Task.Run(() =>
                {
                    MessageBox.Show("Kontrolný súčet sa nezhoduje! Súbor na druhej strane je pravdepodobne poškodený. Zopakujte prenos.",
                        "Súbor poškodený", MessageBoxButton.OK, MessageBoxImage.Warning);
                });
            }

            InvokeAsyncGUI(() =>
            {
                application.MainWindow.statusText.Content = "Súbor bol odoslaný";
                application.MainWindow.sendFileButton.IsEnabled = true;
                application.MainWindow.SetProgress(0, 1);
                application.MainWindow.fileProgressBar.IsIndeterminate = false;
                application.MainWindow.currentConnectionText.Content = "Pripojené";
                application.MainWindow.EnableCipherChange();
            });
        }

        protected bool AuthorizeAccess(bool client = false)
        {
            byte[] rawPublicKey = remoteEndpointPublicKey.Export(KeyBlobFormat.RawPublicKey);
            if (TrustedEndpointsManager.Instance.Lookup(deviceFingerprint, rawPublicKey))
            {
                return true;
            }

            IPEndPoint endpoint = connection.Client.RemoteEndPoint as IPEndPoint;
            AcceptConnectionResult result = Application.Current.Dispatcher.Invoke(() =>
            {
                AcceptConnection acceptConnection = new AcceptConnection(
                    client, remoteComputerName, endpoint.Address.ToString(), deviceFingerprint, rawPublicKey)
                {
                    Owner = application.MainWindow
                };
                acceptConnection.ShowDialog();
                return acceptConnection.Result;
            });

            if (result == AcceptConnectionResult.Reject)
            {
                return false;
            }

            if (result == AcceptConnectionResult.AcceptAndRemember)
            {
                TrustedEndpointsManager.Instance.Add(deviceFingerprint,
                    rawPublicKey, remoteComputerName ?? "");
            }

            return true;
        }

        protected void CommunicationLoop()
        {
            while (connection.Connected)
            {
                try
                {
                    if (connection.Client.Poll(1000, SelectMode.SelectRead))
                    {
                        if (!stream.DataAvailable)
                        {
                            return;
                        }

                        Segment segment = ReceiveEncryptedSegment();

                        switch (segment.Type)
                        {
                            case SegmentType.PREPARE_TRANSFER:
                                ReceiveFile();
                                break;
                            case SegmentType.CIPHER_CHANGE:
                                var cipherChange = (CipherChangeSegment)segment;
                                _ChangeCipher(cipherChange.Algorithm, cipherChange.Salt);
                                break;
                        }
                    }
                    else if (filesToSend.Count > 0)
                    {
                        SendFile();
                    }
                    else
                    {
                        Thread.Sleep(100);
                    }
                }
                catch (SocketException ex)
                {
                    Debug.WriteLine(ex.ToString());
                    break;
                }
            }
        }

        protected void InvokeGUI(Action action)
        {
            if (application.MainWindow == null)
                return;

            Application.Current.Dispatcher.Invoke(action);
        }

        protected void InvokeAsyncGUI(Action action)
        {
            if (application.MainWindow == null)
                return;

            Application.Current.Dispatcher.InvokeAsync(action);
        }

        public void Disconnect()
        {
            stream?.Close();
            connection?.Close();
        }

        public ConcurrentQueue<string> GetFilesToSend()
        {
            return filesToSend;
        }

        public void SetConnected(bool connected)
        {
            this.connected = connected;
            if (connected)
            {
                InvokeGUI(() => application.MainWindow.SetConnected());
                return;
            }

            InvokeGUI(() => application.MainWindow.SetDisconnected());
        }

        public bool IsConnected()
        {
            return connected;
        }

        protected void IncrementNonce()
        {
            for (int i = 5; i >= 0; i--)
            {
                if (lastSequenceForNonce[i] == 255)
                {
                    lastSequenceForNonce[i] = 0;
                    continue;
                }

                lastSequenceForNonce[i]++;
                return;
            }
        }

        protected ulong NonceToUint64(byte[] nonceSeqPart)
        {
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(nonceSeqPart);
            }
            // Using padding [ 255, 255 ]
            byte[] longBytes = nonceSeqPart.Concat(new byte[] { 255, 255 }).ToArray();
            return BitConverter.ToUInt64(longBytes);
        }

        protected string GenerateFreeFileName(string saveFolder, string originalFileName)
        {
            string transformedFileName = originalFileName;
            string savePath = Path.Combine(saveFolder, originalFileName);
            int suffix = 1;
            while (File.Exists(savePath))
            {
                string fileNameWithoutExt = Path.GetFileNameWithoutExtension(originalFileName);
                string ext = Path.GetExtension(originalFileName);

                transformedFileName = fileNameWithoutExt + " (" + suffix + ")" + ext;

                savePath = Path.Combine(saveFolder, transformedFileName);
                suffix++;
            }

            return transformedFileName;
        }
    }
}
