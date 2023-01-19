using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using SecureSend.Protocol;

namespace SecureSend.Base
{
    class IdentityManager
    {
        public const string KNOWN_HOSTS_FILENAME = ".known";

        private static IdentityManager instance;

        public List<Identity> Identities { get; protected set; }

        public static IdentityManager Instance
        {
            get
            {
                if (instance == null)
                {
                    instance = new IdentityManager();
                }
                return instance;
            }
        }

        public IdentityManager()
        {
            Load();
        }

        public void Load()
        {
            Identities = new List<Identity>();

            if (!File.Exists(KNOWN_HOSTS_FILENAME))
            {
                return;
            }

            byte[] bytes = File.ReadAllBytes(KNOWN_HOSTS_FILENAME);
            string entries = UTF8Encoding.UTF8.GetString(bytes, 0, bytes.Length).Trim();
            foreach (string row in entries.Split('\n'))
            {
                string[] parts = row.Trim().Split(':');

                // first part device id
                byte[] deviceFingerprint = Convert.FromHexString(parts[0]);

                // second part public key
                byte[] pubKey = Convert.FromHexString(parts[1]);

                Identities.Append(new Identity(deviceFingerprint, pubKey));
            }
        }

        public void Save() {
            using (StreamWriter fileStream = new StreamWriter(KNOWN_HOSTS_FILENAME, false))
            {
                foreach (Identity identity in Identities)
                {
                    string devFingerprint = Convert.ToHexString(identity.DeviceFingerprint);
                    string pubKey = Convert.ToHexString(identity.PublicKey);
                    fileStream.WriteLine(devFingerprint + ':' + pubKey);
                }
            }
        }

    }
}
