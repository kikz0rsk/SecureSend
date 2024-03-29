﻿using System;
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

            try
            {
                List<Identity> identities = new List<Identity>();

                byte[] bytes = File.ReadAllBytes(KNOWN_HOSTS_FILENAME);
                string entries = UTF8Encoding.UTF8.GetString(bytes, 0, bytes.Length).Trim();
                foreach (string row in entries.Split('\n'))
                {
                    if (row.Trim().Length == 0) continue;

                    string[] parts = row.Trim().Split(':');

                    string computerName = parts[0];

                    // first part device id
                    byte[] hardwareFingerprint = Convert.FromHexString(parts[1]);

                    // second part public key
                    byte[] pubKey = Convert.FromBase64String(parts[2]);

                    identities.Add(new Identity(hardwareFingerprint, pubKey, computerName));
                }

                Identities = identities;
            }
            catch (Exception)
            {
                Identities = new List<Identity>();
            }
        }

        public void Save()
        {
            using (StreamWriter fileStream = new StreamWriter(KNOWN_HOSTS_FILENAME, false))
            {
                foreach (Identity identity in Identities)
                {
                    fileStream.WriteLine(identity.ComputerName + ":"
                        + identity.HardwareFingerprintString + ':'
                        + identity.PublicKeyString);
                }
            }
        }

        public void Add(byte[] deviceFingerprint, byte[] publicKey, string computerName)
        {
            Identities.Add(new Identity(deviceFingerprint, publicKey, computerName));
            Save();
        }

        public bool Lookup(byte[] deviceFingerprint, byte[] publicKey)
        {
            bool result = false;
            foreach (Identity identity in Identities)
            {
                if (Enumerable.SequenceEqual(identity.HardwareFingerprint, deviceFingerprint) &&
                    Enumerable.SequenceEqual(identity.PublicKey, publicKey))
                {
                    return true;
                }
            }

            return result;
        }

        public void RemoveAtIndex(int index)
        {
            Identities.RemoveAt(index);
            Save();
            Load();
        }

        public static byte[] GetHardwareFingerprint()
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
            }
            catch (Exception)
            {
                return "";
            }
            finally
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
            }
            catch (Exception)
            {
                return "";
            }
            finally
            {
                baseboardSearcher.Dispose();
            }
        }

    }
}
