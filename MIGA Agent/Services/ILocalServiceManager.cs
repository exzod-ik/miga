using System;
using System.Collections.Generic;
using System.ServiceProcess;
using System.Text;

namespace MIGA_Agent.Services
{
    public interface ILocalServiceManager
    {
        ServiceControllerStatus? GetStatus();
        void Start();
        void Stop();
        void ReloadConfig();
    }
}
