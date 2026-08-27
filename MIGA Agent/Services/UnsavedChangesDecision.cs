namespace MIGA_Agent.Services
{
    /// <summary>
    /// Решение пользователя при закрытии окна с несохранёнными изменениями.
    /// </summary>
    public enum UnsavedChangesDecision
    {
        /// <summary>Отменить закрытие.</summary>
        Cancel,

        /// <summary>Сохранить изменения и закрыть.</summary>
        Save,

        /// <summary>Закрыть без сохранения.</summary>
        Discard
    }
}
