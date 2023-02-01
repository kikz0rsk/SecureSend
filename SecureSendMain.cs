using SecureSend.Endpoint;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend
{
    class SecureSendMain
    {
        private static SecureSendMain instance;

        public static SecureSendMain Instance
        {
            get
            {
                if (instance == null)
                {
                    instance = new SecureSendMain();
                }
                return instance;
            }
        }

        private SecureSendMain()
        { }

        public NSec.Cryptography.Key? Key { get; set; }

        public Server Server { get; set; }

        public Client Client { get; set; }

        public MainWindow MainWindow { get; set; }

        public bool PasswordAuthEnabled { get; set; }

        public string Username { get; set; }

        public SecureString Password { get; set; }
    }
}
