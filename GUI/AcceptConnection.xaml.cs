using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace SecureSend.GUI
{
    /// <summary>
    /// Interaction logic for AcceptConnection.xaml
    /// </summary>
    public partial class AcceptConnection : Window
    {
        AcceptConnectionResult result = AcceptConnectionResult.Reject;

        public AcceptConnection(bool client, string computerName,
            string ip, byte[] deviceFingerprint, byte[] publicKey)
        {
            InitializeComponent();

            if (client)
            {
                question.Content = "Connect to this device?";
            }
            computerNameAndAddress.Content = computerName + " (" + ip + ")";
            deviceIdentification.Content = Convert.ToHexString(deviceFingerprint);
            identity.Content = Convert.ToBase64String(publicKey);
        }

        private void acceptOnce_Click(object sender, RoutedEventArgs e)
        {
            result = AcceptConnectionResult.AcceptOnce;
            this.Close();
        }

        private void acceptRemember_Click(object sender, RoutedEventArgs e)
        {
            result = AcceptConnectionResult.AcceptAndRemember;
            this.Close();
        }

        private void reject_Click(object sender, RoutedEventArgs e)
        {
            result = AcceptConnectionResult.Reject;
            this.Close();
        }

        public AcceptConnectionResult Result { get { return result; } }
    }
}
