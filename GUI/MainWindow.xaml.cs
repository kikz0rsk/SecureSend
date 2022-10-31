using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using BP.Networking;
using NSec.Cryptography;

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
            KeyCreationParameters paramz = new KeyCreationParameters();
            paramz.ExportPolicy = KeyExportPolicies.AllowPlaintextExport;
            clientKeyPair = NSec.Cryptography.Key.Create(KeyAgreementAlgorithm.X25519, paramz);
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
    }
}
