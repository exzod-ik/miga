using CommunityToolkit.Mvvm.ComponentModel;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Threading;

namespace MIGA_Agent.Services
{
    public enum NotificationKind { Information, Warning, Error, Success, Progress }

    public sealed partial class NotificationEntry : ObservableObject
    {
        [ObservableProperty] private string _title;
        [ObservableProperty] private string _message;
        [ObservableProperty] private NotificationKind _kind;

        public NotificationEntry(string title, string message, NotificationKind kind)
        {
            _title = title;
            _message = message;
            _kind = kind;
        }
    }

    public sealed class NotificationCenter
    {
        private readonly Dictionary<NotificationEntry, DispatcherTimer> _timers = new();
        public ObservableCollection<NotificationEntry> Items { get; } = new();

        public NotificationEntry Show(string title, string message, NotificationKind kind)
        {
            return OnUiThread(() =>
            {
                var existing = Items.FirstOrDefault(item => item.Kind == kind
                    && item.Title == title && item.Message == message);
                if (existing != null)
                {
                    StartTimer(existing);
                    return existing;
                }

                // Ограничиваем только временные сообщения: работающая операция не должна исчезнуть.
                var transient = Items.Where(item => item.Kind != NotificationKind.Progress).ToList();
                if (transient.Count >= 4)
                    Dismiss(transient[0]);

                var entry = new NotificationEntry(title, message, kind);
                Items.Add(entry);
                StartTimer(entry);
                return entry;
            });
        }

        public NotificationEntry ShowProgress(string title)
        {
            return OnUiThread(() =>
            {
                var entry = new NotificationEntry(title, "Подготовка...", NotificationKind.Progress);
                Items.Add(entry);
                return entry;
            });
        }

        public void UpdateProgress(NotificationEntry entry, string title, string message)
        {
            OnUiThread(() =>
            {
                if (!Items.Contains(entry) || entry.Kind != NotificationKind.Progress)
                    return;

                entry.Title = title;
                entry.Message = message;
            });
        }

        public void CompleteProgress(NotificationEntry entry, string title, string message, bool isError)
        {
            OnUiThread(() =>
            {
                if (!Items.Contains(entry))
                    return;

                entry.Title = title;
                entry.Message = message;
                entry.Kind = isError ? NotificationKind.Error : NotificationKind.Success;
                StartTimer(entry);
            });
        }

        public void Dismiss(NotificationEntry entry)
        {
            OnUiThread(() =>
            {
                if (_timers.Remove(entry, out var timer))
                    timer.Stop();
                Items.Remove(entry);
            });
        }

        private void StartTimer(NotificationEntry entry)
        {
            if (_timers.Remove(entry, out var oldTimer))
                oldTimer.Stop();

            var seconds = entry.Kind switch
            {
                NotificationKind.Error => 12,
                NotificationKind.Warning => 8,
                _ => 5
            };
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(seconds) };
            timer.Tick += (_, _) => Dismiss(entry);
            _timers.Add(entry, timer);
            timer.Start();
        }

        private static T OnUiThread<T>(Func<T> action)
        {
            var dispatcher = Application.Current.Dispatcher;
            return dispatcher.CheckAccess() ? action() : dispatcher.Invoke(action);
        }

        private static void OnUiThread(Action action)
        {
            var dispatcher = Application.Current.Dispatcher;
            if (dispatcher.CheckAccess()) action();
            else dispatcher.Invoke(action);
        }
    }
}
