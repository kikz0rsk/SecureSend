using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management;
using System.IO;
using System.Security.Cryptography;

namespace SecureSend.Base
{
    class TrustedEndpointsManager
    {
        public const string KNOWN_HOSTS_FILENAME = ".known";

        private static TrustedEndpointsManager instance = new TrustedEndpointsManager();

        public List<Identity> Identities { get; protected set; }

        public static TrustedEndpointsManager Instance
        {
            get
            {
                return instance;
            }
        }

        private TrustedEndpointsManager()
        {
            Load();
        }

        public void Load()
        {
            if (!File.Exists(KNOWN_HOSTS_FILENAME))
            {
                Identities = new List<Identity>();
                return;
            }

            List<Identity> identities = new List<Identity>();

            byte[] bytes = File.ReadAllBytes(KNOWN_HOSTS_FILENAME);
            string entries = UTF8Encoding.UTF8.GetString(bytes, 0, bytes.Length).Trim();
            foreach (string row in entries.Split('\n'))
            {
                string[] parts = row.Trim().Split(':');

                // first part device id
                byte[] deviceFingerprint = Convert.FromHexString(parts[0]);

                // second part public key
                byte[] pubKey = Convert.FromHexString(parts[1]);

                identities.Add(new Identity(deviceFingerprint, pubKey));
            }

            Identities = identities;
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

        public void Add(byte[] deviceFingerprint, byte[] publicKey)
        {
            Identities.Add(new Identity(deviceFingerprint, publicKey));
            Save();
        }

        public bool Lookup(byte[] deviceFingerprint, byte[] publicKey)
        {
            bool result = false;
            foreach(Identity identity in Identities)
            {
                if(Enumerable.SequenceEqual(identity.DeviceFingerprint, deviceFingerprint) &&
                    Enumerable.SequenceEqual(identity.PublicKey, publicKey))
                {
                    return true;
                }
            }

            return result;
        }

        public static byte[] GetDeviceFingerprint()
        {
            return SHA256.Create().ComputeHash(UTF8Encoding.UTF8.GetBytes(
                GetMotherboardSerialNumber() + GetDiskSerialNumber()));
        }

        protected static string GetDiskSerialNumber()
        {
            ManagementObject disk = new ManagementObject("Win32_LogicalDisk.DeviceID=\"C:\"");

            try
            {
                return disk["VolumeSerialNumber"].ToString() ?? "";
            } catch(Exception)
            {
                return "";
            } finally
            {
                disk.Dispose();
            }
            
        }

        protected static string GetMotherboardSerialNumber()
        {
            ManagementObjectSearcher baseboardSearcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_BaseBoard");

            try
            {
                foreach (ManagementObject queryObj in baseboardSearcher.Get())
                {
                    return queryObj["SerialNumber"].ToString() ?? "";
                }

                return "";
            } catch (Exception)
            {
                return "";
            } finally
            {
                baseboardSearcher.Dispose();
            }
        }

    }
}
