using SecureSend.Base;
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
            Key = IdentityManager.Instance.GetKey();
            ServerPort = 23488;
            AllowUpnp = false;
            AllowIncomingConnections = true;
            Username = "admin";
            Password = "";
        }

        public NSec.Cryptography.Key Key { get; set; }

        public Server Server { get; set; }

        public Client Client { get; set; }

        public MainWindow MainWindow { get; set; }

        public bool PasswordAuthEnabled { get; set; }

        public string Username { get; set; }

        public string Password { get; set; }

        public bool AllowIncomingConnections { get; set; }

        public int ServerPort { get; set; }

        public bool AllowUpnp { get; set; }

        public Server CreateServer()
        {
            if (Server != null)
            {
                Server.StopServer();
            }

            Server server = new Server(this);
            Server = server;
            return server;
        }

        public Client CreateClient()
        {
            if (Client != null)
            {
                Client.Disconnect();
            }

            Client client = new Client(this);
            Client = client;
            return client;
        }
    }
}
