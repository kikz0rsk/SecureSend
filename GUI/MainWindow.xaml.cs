﻿using System;
using System.Windows;
using SecureSend.Endpoint;
using NSec.Cryptography;
using Microsoft.WindowsAPICodePack.Dialogs;
using SecureSend.GUI;
using SecureSend.Utils;
using SecureSend.Base;
using System.Diagnostics;
using SecureSend.Protocol;
using System.Threading.Tasks;
using Open.Nat;
using System.Net;

namespace SecureSend
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private SecureSendApp application;

        Server server;
        Client? client;

        public MainWindow(SecureSendApp application)
        {
            InitializeComponent();

            this.application = application;
            application.MainWindow = this;
            application.UpnpService.OnUpnpSuccess += OnUpnpSuccess;
            application.UpnpService.OnUpnpFail += OnUpnpFail;
            application.UpnpService.OnUpnpDisable += OnUpnpDisabled;
        }

        private void OnUpnpSuccess(Mapping mapping)
        {
            Application.Current.Dispatcher.Invoke(() => {
                upnpPortStatus.Content = "For connections from Internet: " + mapping.PublicIP.ToString() + ":" + mapping.PublicPort.ToString();
            });
        }

        private void OnUpnpFail()
        {
            Application.Current.Dispatcher.Invoke(() => {
                upnpPortStatus.Content = "Failed to create UPnP mapping";
            });
        }

        private void OnUpnpDisabled()
        {
            Application.Current.Dispatcher.Invoke(() => {
                upnpPortStatus.Content = "Connections from Internet disabled";
            });
        }

        private void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            saveFolderLocation.Text = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads\\SecureSend";
            publicKeyText.Text = Convert.ToBase64String(application.Key.PublicKey.Export(KeyBlobFormat.RawPublicKey));

            statusText.Content = "Starting server...";
            server = application.CreateServer();
            server.StartServer();
            statusText.Content = "Ready";
        }

        protected void disconnctBtn_Click(object sender, RoutedEventArgs e)
        {
            if (client != null && client.IsConnected())
            {
                client.Disconnect();
                return;
            }

            if (server.IsConnected())
            {
                server.Disconnect();
                return;
            }
        }

        private void connectBtn_Click(object sender, RoutedEventArgs e)
        {
            if ((client != null && client.IsConnected()) || server.IsConnected())
            {
                return;
            }

            ConnectWindow connectWindow = new ConnectWindow { Owner = this };
            connectWindow.ShowDialog();

            if (connectWindow.IpAddress == null || connectWindow.Port == null)
            {
                return;
            }

            IPAddress address;
            if(!IPAddress.TryParse(connectWindow.IpAddress, out address))
            {
                Task.Run(() =>
                {
                    MessageBox.Show("Address is not valid.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                });
                return;
            }

            ushort port;
            if (!ushort.TryParse(connectWindow.Port, out port)) {
                Task.Run(() =>
                {
                    MessageBox.Show("Port is not valid.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                });
                return;
            }

            if (IPAddress.IsLoopback(address) && port == application.Server.Port)
            {
                Task.Run(() =>
                {
                    MessageBox.Show("Cannot connect to this instance.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                });
                return;
            }

            client = application.CreateClient();
            client.Connect(connectWindow.IpAddress, connectWindow.Port);
        }

        private void onWindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            application.MainWindow = null;
            client?.Disconnect();
            client?.Thread?.Interrupt();

            server?.StopServer();
        }

        private void sendFileButton_Click(object sender, RoutedEventArgs e)
        {
            if ((client != null && client.IsConnected()))
            {
                client.GetFilesToSend().Enqueue(inputFilePath.Text.Trim());
                return;
            }

            if (server.IsConnected())
            {
                server.GetFilesToSend().Enqueue(inputFilePath.Text.Trim());
            }
        }

        public void SetConnected()
        {
            currentConnectionText.Content = "Connected";
            disconnectBtn.IsEnabled = true;
            connectBtn.IsEnabled = false;
            SetProgress(0, 1);
            statusText.Content = "Ready";
            sendFileButton.IsEnabled = true;
        }

        public void SetDisconnected()
        {
            currentConnectionText.Content = "No connection";
            disconnectBtn.IsEnabled = false;
            connectBtn.IsEnabled = true;
            fileProgressBar.IsIndeterminate = false;
            SetProgress(0, 1);
            statusText.Content = "Ready";
            sendFileButton.IsEnabled = false;
        }

        public void SetBusy()
        {
            sendFileButton.IsEnabled = false;
        }

        public void SetReady()
        {
            sendFileButton.IsEnabled = false;
        }

        private void sendFileExploreBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            dialog.CheckFileExists = true;
            dialog.CheckPathExists = true;
            dialog.Filter = "All files|*.*";

            if (dialog.ShowDialog() != true) return;

            inputFilePath.Text = dialog.FileName;
        }

        private void saveLocationExploreBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new CommonOpenFileDialog();
            dialog.IsFolderPicker = true;

            if (dialog.ShowDialog() != CommonFileDialogResult.Ok) return;

            saveFolderLocation.Text = dialog.FileName;
        }

        public void SetProgress(ulong bytesTransfered, ulong totalBytes)
        {
            float percentage = ((float)bytesTransfered / totalBytes * 100);
            if (percentage < 0) { percentage = 0; } else if (percentage > 100) { percentage = 100; }
            this.fileProgressBar.Value = percentage;
            this.progressPercentage.Content = percentage.ToString("F1") + "%";
        }

        private void identityMngrBtn_Click(object sender, RoutedEventArgs e)
        {
            TrustedEndpointsManager.Instance.Load();
            TrustedEndpointsWindow window = new TrustedEndpointsWindow { Owner = this };
            window.Show();
        }

        private void onChangePasswordAuthClick(object sender, RoutedEventArgs e)
        {
            var window = new PasswordAuthSettingsWindow(
                application.PasswordAuthEnabled, application.Username, application.Password)
            { 
                Owner = this
            };
            window.ShowDialog();

            if (!window.ApplyChanges) return;

            application.Username = window.Username;
            application.Password = window.Password;
            application.PasswordAuthEnabled = window.AuthEnabled;
        }

        private void onServerSettingsClick(object sender, RoutedEventArgs e)
        {
            ServerSettingsWindow serverSettingsWindow = new ServerSettingsWindow(
                application.AllowIncomingConnections, application.UpnpService.UpnpEnabled, application.ServerPort)
            {
                Owner = this
            };
            serverSettingsWindow.ShowDialog();

            if (!serverSettingsWindow.ApplyChanges)
            {
                return;
            }

            Debug.WriteLine("apply server changes");
            application.AllowIncomingConnections = serverSettingsWindow.AllowServer;
            application.UpnpService.UpnpEnabled = serverSettingsWindow.AllowUpnp;
            application.ServerPort = serverSettingsWindow.Port;

            if (!serverSettingsWindow.AllowServer)
            {
                Debug.WriteLine("stopping server");
                application.UpnpService.DisableUpnpForward();
                server?.StopServer();
                return;
            }

            server?.StopServer();
            application.ServerPort = serverSettingsWindow.Port;
            application.UpnpService.DisableUpnpForward().ContinueWith(async(e) => {
                if (serverSettingsWindow.AllowUpnp)
                {
                    await application.UpnpService.EnableUpnpForward();
                }
            }, TaskContinuationOptions.None);
            server = application.CreateServer();
            server.StartServer();
        }

        private void onAesSelected(object sender, RoutedEventArgs e)
        {
            byte[] salt = new byte[64];
            CryptoUtils.FillWithRandomBytes(salt);
            if ((client != null && client.IsConnected()))
            {
                client.ChangeCipher(Protocol.CipherAlgorithm.AES256, salt);
                return;
            }

            if (server.IsConnected())
            {
                server.ChangeCipher(Protocol.CipherAlgorithm.AES256, salt);
            }
        }

        private void onChachaSelected(object sender, RoutedEventArgs e)
        {
            byte[] salt = new byte[64];
            CryptoUtils.FillWithRandomBytes(salt);
            if ((client != null && client.IsConnected()))
            {
                client.ChangeCipher(Protocol.CipherAlgorithm.ChaCha20Poly1305, salt);
                return;
            }

            if (server.IsConnected())
            {
                server.ChangeCipher(Protocol.CipherAlgorithm.ChaCha20Poly1305, salt);
            }
        }

        public void SetCipher(CipherAlgorithm algo)
        {
            switch (algo)
            {
                case CipherAlgorithm.AES256:
                    aes256.IsChecked = true;
                    chachapoly1305.IsChecked = false;
                    statusText.Content = "Encryption changed to AES256";
                    break;
                case CipherAlgorithm.ChaCha20Poly1305:
                    aes256.IsChecked = false;
                    chachapoly1305.IsChecked = true;
                    statusText.Content = "Encryption changed to ChaCha20Poly1305";
                    break;
            }
        }

        public void DisableCipherChange()
        {
            cipherChangeSettings.IsEnabled = false;
        }

        public void EnableCipherChange()
        {
            cipherChangeSettings.IsEnabled = true;
        }

        private void Window_Drop(object sender, DragEventArgs e)
        {
            if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;

            string[] paths = (string[])e.Data.GetData(DataFormats.FileDrop);

            if (paths.Length == 0) return;

            inputFilePath.Text = paths[0];
        }

        private void inputFilePath_PreviewDragOver(object sender, DragEventArgs e)
        {
            e.Handled = true;
        }
    }
}
