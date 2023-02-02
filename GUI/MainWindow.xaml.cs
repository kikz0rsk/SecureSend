using System;
using System.Windows;
using SecureSend.Endpoint;
using NSec.Cryptography;
using Microsoft.WindowsAPICodePack.Dialogs;
using SecureSend.GUI;
using SecureSend.Utils;
using SecureSend.Base;

namespace SecureSend
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private NSec.Cryptography.Key? clientKeyPair;
        Server server;
        Client client;

        public MainWindow()
        {
            InitializeComponent();
            SecureSendMain.Instance.MainWindow = this;
            server = new Server(this);
            SecureSendMain.Instance.Server = server;
            client = new Client(this);
            SecureSendMain.Instance.Client = client;
        }

        private void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            statusText.Content = "Načítavanie kľúča...";
            clientKeyPair = IdentityManager.Instance.GetKey();
            publicKeyText.Text = Convert.ToBase64String(clientKeyPair.PublicKey.Export(KeyBlobFormat.RawPublicKey));

            statusText.Content = "Štart servera...";
            server.StartServer();
            statusText.Content = "Pripravené";
        }

        protected void disconnctBtn_Click(object sender, RoutedEventArgs e)
        {
            if (client.IsConnected())
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
            if (client.IsConnected() || server.IsConnected())
            {
                return;
            }

            ConnectWindow connectWindow = new ConnectWindow();
            connectWindow.ShowDialog();

            if(connectWindow.IpAddress == null || connectWindow.Port == null)
            {
                return;
            }

            client.Connect(connectWindow.IpAddress, connectWindow.Port);
        }

        private void onWindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            client.Disconnect();
            client.GetThread()?.Interrupt();

            server.StopServer();
            server.ServerThread?.Join();
        }

        private void sendFileButton_Click(object sender, RoutedEventArgs e)
        {
            if (client.IsConnected())
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
        }

        public void SetDisconnected()
        {
            currentConnectionText.Content = "Žiadne spojenie";
            disconnectBtn.IsEnabled = false;
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

        private void changeLoginCredentials_Click(object sender, RoutedEventArgs e)
        {
            var window = new PasswordAuthWindow(true, SecureSendMain.Instance.Username);
            window.Owner = this;
            window.ShowDialog();

            SecureSendMain.Instance.Username = window.Username;
            SecureSendMain.Instance.Password = window.Password;
        }
    }
}
