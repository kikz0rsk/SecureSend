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
    /// Interaction logic for ConnectForm.xaml
    /// </summary>
    public partial class ConnectWindow : Window
    {
        public ConnectWindow()
        {
            InitializeComponent();
        }

        private void connectBtn_Click(object sender, RoutedEventArgs e)
        {
            if (ipAddress.Text.Trim().Length == 0 || port.Text.Trim().Length == 0)
            {
                return;
            }

            IpAddress = ipAddress.Text;
            Port = port.Text;

            Close();
        }

        public string? IpAddress { get; protected set; }

        public string? Port { get; protected set; }
    }
}
