using System;
using System.Collections.Generic;
using System.Diagnostics;
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
    /// Interaction logic for PasswordAuthSettingsWindow.xaml
    /// </summary>
    public partial class PasswordAuthSettingsWindow : Window
    {
        public PasswordAuthSettingsWindow(bool authEnabled, string username, string password)
        {
            InitializeComponent();

            authEnabledCheckbox.IsChecked = authEnabled;
            this.username.Text = username;
            this.password.Password = password;
        }

        private void authEnabledCheckbox_Checked(object sender, RoutedEventArgs e)
        {
            username.IsEnabled = true;
            password.IsEnabled = true;
        }

        private void saveButton_Click(object sender, RoutedEventArgs e)
        {
            if (authEnabledCheckbox.IsChecked == true)
            {
                if (password.Password.Length == 0 || username.Text.Trim().Length == 0) return;

                AuthEnabled = true;
                Username = username.Text;
                Password = password.Password;
                ApplyChanges = true;
                Close();
                return;
            }

            AuthEnabled = false;
            Close();
            return;
        }

        private void authEnabledCheckbox_Unchecked(object sender, RoutedEventArgs e)
        {
            username.IsEnabled = false;
            password.IsEnabled = false;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            if (authEnabledCheckbox.IsChecked == true)
            {
                authEnabledCheckbox_Checked(null, null);
            }
            else
            {
                authEnabledCheckbox_Unchecked(null, null);
            }
        }

        public bool AuthEnabled { get; protected set; }
        public bool ApplyChanges { get; protected set; }
        public string Username { get; protected set; }
        public string Password { get; protected set; }
    }
}
