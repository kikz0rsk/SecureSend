using NSec.Cryptography;
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace BP
{
    internal class Client
    {
        private string ipAddress;
        private string port;
        public TcpClient connection;
        private MainWindow mainWindow;

        public Client(string ipAddress, string port, MainWindow mainWindow)
        {
            this.ipAddress = ipAddress;
            this.port = port;
            this.mainWindow = mainWindow;
        }

        public void Start()
        {
            try
            {
                connection = new TcpClient();
                connection.Connect(IPAddress.Parse(ipAddress), int.Parse(port));
                EstablishTrust();
                connection.Close();
            } catch(ThreadInterruptedException inter)
            {
                connection.Close();
            }
        }

        public Key? EstablishTrust()
        {
            NetworkStream channel = connection.GetStream();

            // send public key
            channel.Write(mainWindow.ClientKeyPair.PublicKey.Export(KeyBlobFormat.RawPublicKey));

            // get server's public key
            byte[] serverPublicKeyRaw = new byte[32];
            channel.Read(serverPublicKeyRaw, 0, 32);

            PublicKey serverPublicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, serverPublicKeyRaw, KeyBlobFormat.RawPublicKey);

            // agree on shared secret
            SharedSecret sharedSecret = KeyAgreementAlgorithm.X25519.Agree(mainWindow.ClientKeyPair, serverPublicKey);

            if(sharedSecret == null)
            {
                connection.Close();
                return null;
            }

            return KeyDerivationAlgorithm.HkdfSha512.DeriveKey(sharedSecret, null, serverPublicKeyRaw, AeadAlgorithm.Aes256Gcm);

        }
    }
}
