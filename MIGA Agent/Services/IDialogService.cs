using Notification.Wpf.Classes;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace MIGA_Agent.Services
{
    public interface IDialogService
    {
        /// <summary>
        /// Показать информационное сообщение
        /// </summary>
        void ShowInfo(string message, string title = "Информация");

        /// <summary>
        /// Показать предупреждение
        /// </summary>
        void ShowWarning(string message, string title = "Предупреждение");

        /// <summary>
        /// Показать ошибку
        /// </summary>
        void ShowError(string message, string title = "Ошибка");

        /// <summary>
        /// Показать диалог подтверждения (Yes/No)
        /// </summary>
        bool ShowYesNo(string message, string title = "Подтверждение");

        /// <summary>
        /// Показать диалог с выбором действия при несохранённых изменениях
        /// (Сохранить / Не сохранять / Отмена).
        /// </summary>
        UnsavedChangesDecision ShowUnsavedChangesDialog(string message, string title = "Несохранённые изменения");

        /// <summary>
        /// Показать диалог со списком проблем конфигурации.
        /// Возвращает true, если пользователь выбрал "все равно применить", false — отмена.
        /// </summary>
        bool ShowIssuesConfirmation(string title, string message, IEnumerable<string> issues);

        /// <summary>
        /// Показать диалог выбора папки
        /// </summary>
        string? ShowFolderDialog(string description = "Выберите папку", string? selectedPath = null);

        /// <summary>
        /// Показать диалог ввода текста
        /// </summary>
        string? ShowInputDialog(string prompt, string title = "Ввод", string defaultValue = "");

        /// <summary>
        /// Показать диалог многострочного ввода текста
        /// </summary>
        string? ShowMultiLineInputDialog(string prompt, string title, string defaultValue = "");

        /// <summary>
        /// Показать "липкое" уведомление
        /// </summary>
        NotifierProgress<Notification.Core.NotificationProgressReport> ShowPersistent(string title);

        /// <summary>
        /// Обновить "липкое" уведомление
        /// </summary>
        void UpdatePersistent(NotifierProgress<Notification.Core.NotificationProgressReport> notification, string title, string message);

        /// <summary>
        /// Закрыть "липкое" уведомление
        /// </summary>
        void ClosePersistent(NotifierProgress<Notification.Core.NotificationProgressReport> notification, string title, string message);
    }
}