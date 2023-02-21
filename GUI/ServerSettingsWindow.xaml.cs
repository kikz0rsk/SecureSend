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
    /// Interaction logic for ServerSettingsWindow.xaml
    /// </summary>
    public partial class ServerSettingsWindow : Window
    {

        public ServerSettingsWindow(bool allowServer, bool allowUpnp, int port)
        {
            InitializeComponent();

            this.allowServer.IsChecked = allowServer;
            this.allowUpnp.IsChecked = allowUpnp;
            portTextbox.Text = port.ToString();
        }

        private void okButton_Click(object sender, RoutedEventArgs e)
        {
            string text = portTextbox.Text.Trim();

            if(text.Length == 0) return;

            try
            {
                Port = int.Parse(text);
            } catch(Exception)
            {
                return;
            }

            AllowUpnp = allowUpnp.IsChecked ?? false;
            AllowServer = allowServer.IsChecked ?? false;
            ApplyChanges = true;
            this.Close();
        }

        public bool AllowUpnp { get; private set; }
        public bool AllowServer { get; private set; }
        public bool ApplyChanges { get; private set; }
        public int Port { get; private set; }
    }
}
