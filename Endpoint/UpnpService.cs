using Open.Nat;
using SecureSend.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureSend.Endpoint
{
    public class UpnpService
    {
        private SecureSendApp app;
        private Mapping? mapping;
        private NatDevice? natDevice;
        private Mutex mutex;

        public bool UpnpEnabled { get; set; }

        public event UpnpSuccessEventHandler OnUpnpSuccess;
        public event UpnpFailEventHandler OnUpnpFail;
        public event UpnpDisableEventHandler OnUpnpDisable;

        public delegate void UpnpSuccessEventHandler(Mapping mapping);
        public delegate void UpnpFailEventHandler();
        public delegate void UpnpDisableEventHandler();

        public UpnpService(SecureSendApp app)
        {
            this.app = app;
        }

        public async Task EnableUpnpForward()
        {
            Debug.WriteLine("[UPnP] enable");
            //mutex.WaitOne();
            if (this.mapping != null) return;

            try
            {
                var discoverService = new NatDiscoverer();
                var cts = new CancellationTokenSource(10000);
                this.natDevice = await discoverService.DiscoverDeviceAsync(PortMapper.Upnp, cts);
                int attempt = 1;
                int publicPort = 23488;
                bool success = false;
                while (attempt < 10)
                {
                    try
                    {
                        Mapping mapping = new Mapping(Open.Nat.Protocol.Tcp, app.ServerPort, publicPort, "SecureSend");
                        await natDevice.CreatePortMapAsync(mapping);
                        success = true;
                        this.mapping = mapping;
                        break;
                    }
                    catch (MappingException ex)
                    {
                        Debug.WriteLine("[UPnP] mapping exception: " + ex.ToString());
                        Debug.WriteLine("[UPnP] trying random port");
                        publicPort = (CryptoUtils.GetRandomInstance().Next()) % (65_535 - 5_000) + 5_000;
                        attempt++;
                    }
                    catch (Exception)
                    { 
                        break;
                    }
                }

                if (success)
                {
                    Debug.WriteLine("[UPnP] successfully setup port forward");
                    this.OnUpnpSuccess?.Invoke(this.mapping);
                } else
                {
                    this.OnUpnpFail?.Invoke();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[UPnP] general exception: " + ex.ToString());
                this.OnUpnpFail?.Invoke();
            } finally
            {
                //mutex.ReleaseMutex();
            }
        }
        public async Task DisableUpnpForward()
        {
            //mutex.WaitOne();
            if (natDevice == null || mapping == null) return;

            try
            {
                await natDevice.DeletePortMapAsync(mapping);

                mapping = null;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[UPnP] Exception while disabling: " + ex.ToString());
            } finally
            {
                OnUpnpDisable?.Invoke();
                //mutex.ReleaseMutex();
            }
        }

    }
}
