using CommunityToolkit.Mvvm.ComponentModel;

namespace MIGA_Agent.ViewModels
{
    /// <summary>
    /// Элемент списка перенаправления (процесс/IP/домен) с признаком пересечения с другими серверами.
    /// </summary>
    public partial class RedirectItemViewModel : ObservableObject
    {
        public string Value { get; }

        /// <summary>Значение совпадает минимум у двух серверов.</summary>
        [ObservableProperty]
        private bool _isConflicting;

        /// <summary>Подсказка: с какими серверами есть пересечение.</summary>
        [ObservableProperty]
        private string _conflictTooltip = string.Empty;

        public RedirectItemViewModel(string value)
        {
            Value = value;
        }

        public override string ToString() => Value;
    }
}
