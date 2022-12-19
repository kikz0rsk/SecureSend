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

namespace BP.GUI
{
    /// <summary>
    /// Interaction logic for AcceptConnection.xaml
    /// </summary>
    public partial class AcceptConnection : Window
    {
        AcceptConnectionResult result = AcceptConnectionResult.Reject;

        public AcceptConnection(bool client, DeviceId deviceId)
        {
            InitializeComponent();

            if(client)
            {
                question.Content = "Chcete sa pripojiť na toto zariadenie?";
            }
            ipAddr.Content = deviceId.Ip;
            identity.Content = Convert.ToBase64String(deviceId.PublicKey.Export(KeyBlobFormat.RawPublicKey));
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
