using System.IO;
using System.Net.Sockets;
using System.Text.Json;
using Renci.SshNet.Common;

namespace MIGA_Agent.Services;

public sealed class SshCommandFailure : IOException
{
    public int? ExitStatus { get; }

    public SshCommandFailure(string response, int? exitStatus = null, string diagnostic = "")
        : base(FormatMessage(response, exitStatus, diagnostic))
    {
        ExitStatus = exitStatus;
    }

    private static readonly HashSet<string> KnownReasons = new(StringComparer.Ordinal)
    {
        "invalid_server_configuration", "invalid_interface", "invalid_log_level", "invalid_dns_server",
        "unsupported_state_directory", "unsupported_existing_protocol", "unknown_legacy_configuration",
        "invalid_legacy_ports", "invalid_legacy_keys", "automatic_interface_unavailable", "invalid_outgoing_interface",
        "unsafe_backup_symlink", "persistent_firewall_conflict", "rollback_temporary_exists", "rollback_displaced_exists",
        "backup_restore_failed", "unsupported_service_state", "unsupported_service_command", "running_server_identity_unknown",
        "running_server_command_unknown", "legacy_restart_failed", "legacy_restart_identity_unknown", "legacy_restart_timeout",
        "server_start_failed", "server_readiness_timeout", "dependency_preparation_failed", "invalid_server_host",
        "duplicate_configuration_key", "invalid_existing_server_host", "unsupported_legacy_version", "unexpected_candidate_version",
        "unsupported_service_unit_path", "unsupported_service_overrides", "service_unit_reload_required",
        "invalid_forwarding_state", "server_update_interrupted", "root_required", "systemd_required",
        "unsupported_package_manager", "package_command_failed", "legacy_configuration_expected", "virtual_subnet_conflict",
        "invalid_control_range", "control_port_conflict", "legacy_icmp_persistence_not_regular",
        "missing_dependency_python3", "missing_dependency_ip", "missing_dependency_iptables", "missing_dependency_conntrack",
        "missing_dependency_systemctl", "missing_dependency_install", "missing_dependency_sysctl", "missing_dependency_ethtool",
        "missing_dependency_bash", "missing_dependency_cp", "missing_dependency_awk",
        "missing_bootstrap_bash", "missing_bootstrap_timeout", "missing_bootstrap_install", "missing_bootstrap_cp",
        "missing_bootstrap_mktemp", "missing_bootstrap_chmod", "missing_bootstrap_mv", "missing_bootstrap_rm",
        "missing_bootstrap_cat", "missing_bootstrap_dirname", "missing_bootstrap_readlink", "missing_bootstrap_ln",
        "missing_bootstrap_mkdir", "missing_bootstrap_rmdir", "missing_bootstrap_sha256sum",
        "server_binary_execution_failed", "server_binary_checksum_failed", "server_binary_missing"
    };

    private static string FormatMessage(string response, int? exitStatus, string diagnostic)
    {
        string details = SafeDiagnostic(diagnostic);
        string? serverMessage = ServerMessage(response);
        string message = serverMessage == null
            ? (details.Length == 0 ? "Команда на сервере завершилась с ошибкой." : details)
            : (details.Length == 0 ? serverMessage : serverMessage + " " + details);
        return message + " Код завершения " +
            (exitStatus?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "неизвестен") + ".";
    }

    private static string SafeDiagnostic(string diagnostic)
    {
        if (diagnostic.Length > 1024 * 1024) return "";
        var details = new List<string>();
        foreach (string source in diagnostic.Split('\n'))
        {
            string line = source.TrimEnd('\r');
            string? message = line switch
            {
                "root_required" => "Для установки нужны права root.",
                "invalid_outgoing_interface" => "Выходной интерфейс не найден или его имя недопустимо. Проверьте имя командой ip -4 route show default.",
                "automatic_interface_unavailable" => "Не удалось определить выходной интерфейс по маршруту IPv4. Укажите его вручную.",
                "server_binary_execution_failed" => "На сервере не запускается загруженный miga_server. Проверьте архитектуру и совместимость пакета с системой.",
                "unexpected_candidate_version" => "Версия загруженного miga_server не совпадает с версией из ServerVersion.inc. Проверьте комплект установщика.",
                "server_binary_checksum_failed" => "Не удалось подтвердить контрольную сумму загруженного miga_server.",
                "server_install_error stage=stop_service" => "Не удалось остановить службу miga_server.",
                "server_install_error stage=rx_ring" => "Не удалось настроить очередь приёма сетевого адаптера. Проверьте журнал службы miga-rx-ring.",
                "server_install_error stage=install_files" => "Не удалось разместить файлы MIGA на сервере.",
                "server_install_error stage=ip_forward" => "Не удалось включить переадресацию IPv4.",
                "server_install_error stage=start_service" => "Не удалось запустить службу miga_server. Проверьте её журнал.",
                "server_install_error stage=legacy_firewall" => "Не удалось удалить устаревшее правило ICMP.",
                _ => null
            };
            if (message != null) details.Add(message);
            else if (KnownReasons.Contains(line)) details.Add("reason=" + line + ".");
            else if (line.StartsWith("server_update_error reason=", StringComparison.Ordinal) && KnownReasons.Contains(line["server_update_error reason=".Length..])) details.Add(line);
            else
            {
                var match = System.Text.RegularExpressions.Regex.Match(line, @"\Aserver_dependency_error manager=(none|apt-get|dnf|yum) stage=(preflight|refresh|install|verify) reason=([a-z0-9_]+) code=([0-9]{1,3})\z");
                if (match.Success && KnownReasons.Contains(match.Groups[3].Value) && int.TryParse(match.Groups[4].Value, out int code) && code <= 255)
                    details.Add(match.Value);
            }
            if (details.Count == 4) break;
        }
        return string.Join(" ", details);
    }

    private static string? ServerMessage(string response)
    {
        if (response.Length <= 1024 * 1024)
        {
            try
            {
                using var document = JsonDocument.Parse(response);
                if (document.RootElement.ValueKind == JsonValueKind.Object &&
                    document.RootElement.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String)
                {
                    string? message = error.GetString() switch
                    {
                        "invalid_limit" => "Проверьте допустимые значения лимитов.",
                        "invalid_id" or "client_not_found" => "Клиент не найден. Обновите список клиентов и выберите клиента повторно.",
                        "client_add_failed" or "client_update_failed" or "client_revoke_failed" or "database_unavailable" => "Сервер не смог записать данные клиентов. Проверьте доступность базы и свободное место на сервере.",
                        "config_read_failed" or "config_write_failed" or "config_sync_failed" => "Сервер не смог сохранить настройки. Проверьте права и свободное место на сервере.",
                        "invalid_request" or "unknown_operation" or "unknown_scope" => "Сервер не поддерживает запрос. Обновите MIGA Admin и сервер до совместимой версии.",
                        "unsupported_time_service" => "Для активной службы NTP запуск синхронизации из MIGA Admin недоступен.",
                        _ => null
                    };
                    if (message != null) return message + " reason=" + error.GetString();
                }
            }
            catch (JsonException) { }
        }
        return null;
    }
}

public static class SshCommandErrors
{
    public static string UserMessage(Exception error) => error switch
    {
        SshCommandFailure failure => failure.Message,
        SshOperationTimeoutException or TimeoutException or OperationCanceledException => "Истекло время ожидания сервера. Отключитесь и подключитесь к серверу повторно перед следующей командой.",
        InvalidDataException => "Проверьте имя клиента и лимиты. Если значения корректны, обновите MIGA Admin и сервер до совместимой версии.",
        JsonException or FormatException or OverflowException or KeyNotFoundException => "Получен неподдерживаемый ответ сервера. Обновите MIGA Admin и сервер до совместимой версии.",
        SshException or SocketException or IOException or ObjectDisposedException or InvalidOperationException => "SSH-соединение недоступно. Отключитесь и подключитесь к серверу повторно перед следующей командой.",
        _ => "Команда не выполнена. Проверьте SSH, версию сервера и права администратора."
    };
}
