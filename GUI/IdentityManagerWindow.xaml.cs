using SecureSend.Base;
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
    /// Interaction logic for IdentityManager.xaml
    /// </summary>
    public partial class IdentityManagerWindow : Window
    {

        public IdentityManagerWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            foreach(Identity identity in IdentityManager.Instance.Identities)
            {
                list.Items.Add(identity);
            }
        }
    }
}
