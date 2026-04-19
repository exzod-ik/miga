using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Threading.Tasks;

namespace InstallerCustomActions
{
    [RunInstaller(true)]
    public partial class MyInstaller : System.Configuration.Install.Installer
    {
        public MyInstaller()
        {
            InitializeComponent();

            // Проверяем, не запущены ли мы уже с правами администратора
            // Для этого смотрим на аргумент командной строки --elevated
            string[] args = Environment.GetCommandLineArgs();
            bool alreadyElevated = false;
            foreach (string arg in args)
            {
                if (arg.Equals("--elevated", StringComparison.OrdinalIgnoreCase))
                {
                    alreadyElevated = true;
                    break;
                }
            }

            if (!alreadyElevated && !IsCurrentProcessElevated())
            {
                RestartAsAdministrator();
            }
        }

        /// <summary>
        /// Проверяет, запущен ли текущий процесс с правами администратора.
        /// </summary>
        private bool IsCurrentProcessElevated()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>
        /// Перезапускает текущее приложение с запросом прав администратора.
        /// </summary>
        private void RestartAsAdministrator()
        {
            string exePath = Assembly.GetExecutingAssembly().Location;
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,
                Verb = "runas",               // Запрашиваем повышение прав
                Arguments = "--elevated"      // Передаём метку, чтобы не перезапускаться снова
            };

            try
            {
                Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                string logPath = Path.Combine(Path.GetTempPath(), "MigaInstallError.log");
                File.WriteAllText(logPath, $"RestartAsAdministrator failed: {ex.Message}\n{ex.StackTrace}");
                throw new InstallException("Не удалось получить права администратора. Установка прервана.");
            }

            Environment.Exit(0);
        }

        /// <summary>
        /// Возвращает директорию, куда установлено приложение (там же лежит miga_client.exe).
        /// </summary>
        private string GetInstallDirectory()
        {
            string dllPath = Assembly.GetExecutingAssembly().Location;
            return Path.GetDirectoryName(dllPath);
        }

        /// <summary>
        /// Запускает miga_client.exe с указанными аргументами.
        /// </summary>
        private void RunMigaClient(string arguments)
        {
            string installDir = GetInstallDirectory();
            string clientPath = Path.Combine(installDir, "miga_client.exe");

            // Логируем начало работы и путь к файлу
            string logPath = Path.Combine(Path.GetTempPath(), "MigaInstallDebug.log");
            File.AppendAllText(logPath, $"{DateTime.Now}: RunMigaClient called with args '{arguments}'\n");
            File.AppendAllText(logPath, $"{DateTime.Now}: Looking for client at '{clientPath}'\n");

            if (!File.Exists(clientPath))
            {
                File.AppendAllText(logPath, $"{DateTime.Now}: ERROR - File NOT FOUND at '{clientPath}'\n");
                return;
            }

            File.AppendAllText(logPath, $"{DateTime.Now}: File found. Starting process...\n");

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = clientPath,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            try
            {
                using (Process process = Process.Start(startInfo))
                {
                    process.WaitForExit();
                    int exitCode = process.ExitCode;
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();

                    File.AppendAllText(logPath, $"{DateTime.Now}: Process finished with exit code: {exitCode}\n");
                    if (!string.IsNullOrEmpty(output))
                        File.AppendAllText(logPath, $"{DateTime.Now}: STDOUT:\n{output}\n");
                    if (!string.IsNullOrEmpty(error))
                        File.AppendAllText(logPath, $"{DateTime.Now}: STDERR:\n{error}\n");
                }
            }
            catch (Exception ex)
            {
                File.AppendAllText(logPath, $"{DateTime.Now}: EXCEPTION: {ex.Message}\n{ex.StackTrace}\n");
            }
        }

        // Выполняется ПОСЛЕ успешной установки
        protected override void OnAfterInstall(IDictionary savedState)
        {
            base.OnAfterInstall(savedState);
            RunMigaClient("--install");
        }

        // Выполняется ПЕРЕД удалением
        protected override void OnBeforeUninstall(IDictionary savedState)
        {
            base.OnBeforeUninstall(savedState);
            RunMigaClient("--uninstall");
        }
    }
}
