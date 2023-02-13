using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace SecureSend
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        void onStartup(object sender, StartupEventArgs e)
        {
            SecureSendApp application = new SecureSendApp();
            MainWindow window = new MainWindow(application);

            window.Show();
        }
    }
}
