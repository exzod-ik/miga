using System;
using System.Collections.Generic;
using System.Text;
using MIGA_Agent.Models;
using System.Threading.Tasks;

namespace MIGA_Agent.Services
{
    public interface IClientConfigService
    {
        /// <summary>
        /// Путь к файлу конфигурации
        /// </summary>
        string ConfigFilePath { get; set; }

        /// <summary>
        /// Загрузить конфигурацию из файла
        /// </summary>
        Task<ClientConfig> LoadAsync();

        /// <summary>
        /// Сохранить конфигурацию в файл
        /// </summary>
        Task SaveAsync(ClientConfig config);
    }
}
