using SecureSend.Endpoint;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend
{
    public class SecureSendApp
    {
        public SecureSendApp()
        {
            PasswordAuthEnabled = false;
        }

        public NSec.Cryptography.Key? Key { get; set; }

        public Server Server { get; set; }

        public Client Client { get; set; }

        public MainWindow MainWindow { get; set; }

        public bool PasswordAuthEnabled { get; set; }

        public string Username { get; set; }

        public string Password { get; set; }
    }
}
