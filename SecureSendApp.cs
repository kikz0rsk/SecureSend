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
            UpnpService = new UpnpService(this);
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

        public UpnpService UpnpService { get; set; }

        public Server CreateServer()
        {
            if (Server != null)
            {
                Server.StopServer();
            }

            Server = new Server(this);
            return Server;
        }

        public Client CreateClient()
        {
            if (Client != null)
            {
                Client.Disconnect();
            }

            Client = new Client(this);
            return Client;
        }
    }
}
