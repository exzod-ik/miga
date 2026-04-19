using System;
using System.Collections.Generic;
using System.ServiceProcess;
using System.Text;

namespace MIGA_Agent.Services
{
    public class LocalServiceManager : ILocalServiceManager
    {
        private const string ServiceName = "MigaClient";

        public ServiceControllerStatus? GetStatus()
        {
            try
            {
                using var sc = new ServiceController(ServiceName);
                return sc.Status;
            }
            catch
            {
                return null;
            }
        }

        public void Start()
        {
            using var sc = new ServiceController(ServiceName);
            if (sc.Status != ServiceControllerStatus.Running && sc.Status != ServiceControllerStatus.StartPending)
            {
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            }
        }

        public void Stop()
        {
            using var sc = new ServiceController(ServiceName);
            if (sc.Status != ServiceControllerStatus.Stopped && sc.Status != ServiceControllerStatus.StopPending)
            {
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            }
        }
        public void ReloadConfig()
        {
            using var sc = new ServiceController(ServiceName);
            if (sc.Status != ServiceControllerStatus.Running)
            {
                return;
            }
            const int reloadCommand = 128;
            sc.ExecuteCommand(reloadCommand);
        }
    }
}
