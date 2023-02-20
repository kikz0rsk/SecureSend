using System;
using System.Windows;
using SecureSend.Endpoint;
using NSec.Cryptography;
using Microsoft.WindowsAPICodePack.Dialogs;
using SecureSend.GUI;
using SecureSend.Utils;
using SecureSend.Base;
using System.Diagnostics;

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
        }

        private void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            saveFolderLocation.Text = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads";
            publicKeyText.Text = Convert.ToBase64String(application.Key.PublicKey.Export(KeyBlobFormat.RawPublicKey));

            statusText.Content = "Štart servera...";
            server = application.CreateServer();
            server.StartServer();
            statusText.Content = "Pripravené";
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

            ConnectWindow connectWindow = new ConnectWindow();
            connectWindow.Owner = this;
            connectWindow.ShowDialog();

            if (connectWindow.IpAddress == null || connectWindow.Port == null)
            {
                return;
            }

            client = new Client(application);
            application.Client = client;
            client.Connect(connectWindow.IpAddress, connectWindow.Port);
        }

        private void onWindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            client?.Disconnect();
            client?.GetThread()?.Interrupt();

            server?.StopServer();
            server?.ServerThread?.Join();
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
            currentConnectionText.Content = "Pripojené";
            disconnectBtn.IsEnabled = true;
            connectBtn.IsEnabled = false;
            SetProgress(0, 1);
            statusText.Content = "Pripravené";
            sendFileButton.IsEnabled = true;
        }

        public void SetDisconnected()
        {
            currentConnectionText.Content = "Žiadne spojenie";
            disconnectBtn.IsEnabled = false;
            connectBtn.IsEnabled = true;
            SetProgress(0, 1);
            statusText.Content = "Pripravené";
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
            dialog.Filter = "Všetky súbory|*.*";

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
            TrustedEndpointsWindow window = new TrustedEndpointsWindow();
            window.Show();
        }

        private void onChangePasswordAuthClick(object sender, RoutedEventArgs e)
        {
            var window = new PasswordAuthWindow(true, application.Username);
            window.Owner = this;
            window.ShowDialog();

            application.Username = window.Username;
            application.Password = window.Password;
            application.PasswordAuthEnabled = true;
        }

        private void onAllowIncomingConnectionsClick(object sender, RoutedEventArgs e)
        {
            Debug.WriteLine("onAllowIncomingConnectionsClick");
            Debug.WriteLine("isChecked: " + allowIncomingConnections.IsChecked.ToString());
            if (allowIncomingConnections.IsChecked)
            {
                Debug.WriteLine("disable incoming connections");
                allowIncomingConnections.IsChecked = false;
                server.StopServer();
                statusPortText.Content = "Pripojenie na toto zariadenia nie je povolené";
                return;
            }

            Debug.WriteLine("enable incoming connections");
            allowIncomingConnections.IsChecked = true;
            server = new Server(application);
            application.Server = server;
            server.StartServer();
        }
    }
}
