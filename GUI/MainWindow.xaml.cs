using System;
using System.Windows;
using BP.Networking;
using NSec.Cryptography;
using Microsoft.WindowsAPICodePack.Dialogs;

namespace BP
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
            server = new Server(this);
            client = new Client(this);
        }

        private void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            statusText.Content = "Vytváranie kľúčov...";
            clientKeyPair = NSec.Cryptography.Key.Create(KeyAgreementAlgorithm.X25519, CryptoUtils.AllowExport());
            publicKeyText.Text = Convert.ToBase64String(clientKeyPair.PublicKey.Export(KeyBlobFormat.RawPublicKey));

            statusText.Content = "Štart servera...";
            server.StartServer();
            statusText.Content = "Pripravené";
        }

        public NSec.Cryptography.Key? ClientKeyPair { 
            get { return clientKeyPair; }
        }

        private void connectBtn_Click(object sender, RoutedEventArgs e)
        {
            if(client.IsConnected())
            {
                client.Disconnect();
            } else if (server.IsConnected())
            {
                server.Disconnect();
            } else
            {
                client.Connect(ipAddressInput.Text, portInput.Text);
            }
        }

        private void onWindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            client.Disconnect();
            client.GetThread()?.Interrupt();

            server.StopServer();
            server.GetThread()?.Join();
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
            connectBtn.Content = "Odpojiť sa";
        }

        public void SetDisconnected()
        {
            currentConnectionText.Content = "Žiadne spojenie";
            connectBtn.Content = "Pripojiť sa";
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
    }
}
