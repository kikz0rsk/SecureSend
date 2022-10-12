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

using NSec.Cryptography;

namespace BP
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private NSec.Cryptography.Key? clientKeyPair;
        Server? server;
        Client? client;

        private Thread serverThread;
        private Thread clientThread;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            statusText.Content = "Generating keypair...";
            KeyCreationParameters paramz = new KeyCreationParameters();
            paramz.ExportPolicy = KeyExportPolicies.AllowPlaintextExport;
            clientKeyPair = NSec.Cryptography.Key.Create(KeyAgreementAlgorithm.X25519, paramz);
            publicKeyText.Text = Convert.ToBase64String(clientKeyPair.PublicKey.Export(KeyBlobFormat.RawPublicKey));

            statusText.Content = "Starting server...";
            RunServer();
            statusText.Content = "Idle";
        }

        private void RunServer()
        {
            server = new Server(this);
            serverThread = new Thread(server.Start);
            serverThread.Start();
        }

        public NSec.Cryptography.Key? ClientKeyPair { 
            get { return clientKeyPair; }
        }

        private void connectBtn_Click(object sender, RoutedEventArgs e)
        {
            client = new Client(ipAddressInput.Text, portInput.Text, this);
            clientThread = new Thread(client.Start);
            clientThread.Start();
        }

        private void onWindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (clientThread != null)
            {
                client.connection.Close();
                client.connection.Dispose();
                clientThread.Interrupt();
            }
            
            if(serverThread != null)
            {
                server.tcpListener.Stop();
                serverThread.Interrupt();
            }
        }
    }
}
