using System;
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
        NSec.Cryptography.Key? clientKeyPair;
        Server? server;
        
        public MainWindow()
        {
            InitializeComponent();            
        }

        private void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            statusText.Content = "Generating keypair...";
            clientKeyPair = NSec.Cryptography.Key.Create(SignatureAlgorithm.Ed25519);
            
            statusText.Content = "Starting server...";
            RunServer();
            statusText.Content = "Idle";
        }

        private void RunServer()
        {
            server = new Server(this);
            Thread serverThread = new Thread(server.Start);
            serverThread.Start();
        }
    }
}
