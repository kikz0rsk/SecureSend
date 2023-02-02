using Org.BouncyCastle.Utilities.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
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
    public partial class PasswordAuthWindow : Window
    {
        public PasswordAuthWindow(bool changePassword, string? username)
        {
            InitializeComponent();

            if(changePassword)
            {
                this.button.Content = "Zmeniť údaje";
            }

            if(username != null)
            {
                this.username.Text = username;
            }
        }

        private void connectBtn_Click(object sender, RoutedEventArgs e)
        {
            if(username.Text.Trim().Length == 0 || password.Password.Length == 0)
            {
                return;
            }

            Username = this.username.Text;
            Password = this.password.Password;

            Close();
        }

        public string? Username { get; protected set; }

        public string? Password { get; protected set; }
    }
}
