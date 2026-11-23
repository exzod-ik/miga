namespace MIGA_Agent.Services;

public sealed class AdminServerAutosave
{
    private readonly Func<IReadOnlyList<ManagedServerEntry>, Task> save;
    private readonly Action saved;
    private readonly Action<Exception> failed;
    private readonly TimeSpan debounce;
    private readonly SemaphoreSlim gate = new(1, 1);
    private IReadOnlyList<ManagedServerEntry> snapshot = Array.Empty<ManagedServerEntry>();
    private CancellationTokenSource? pending;
    private long revision;
    private long savedRevision;
    public bool HasPending => revision != savedRevision;

    public AdminServerAutosave(Func<IReadOnlyList<ManagedServerEntry>, Task> save, Action saved, Action<Exception> failed, TimeSpan? debounce = null)
    {
        this.save = save;
        this.saved = saved;
        this.failed = failed;
        this.debounce = debounce ?? TimeSpan.FromMilliseconds(500);
    }

    public void Schedule(IEnumerable<ManagedServerEntry> servers)
    {
        snapshot = servers.ToArray();
        revision++;
        pending?.Cancel();
        var cancellation = new CancellationTokenSource();
        pending = cancellation;
        _ = SaveAfterDelayAsync(cancellation);
    }

    private async Task SaveAfterDelayAsync(CancellationTokenSource cancellation)
    {
        try
        {
            await Task.Delay(debounce, cancellation.Token);
            await FlushAsync();
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (Exception error) { failed(error); }
        finally
        {
            if (ReferenceEquals(pending, cancellation)) pending = null;
            cancellation.Dispose();
        }
    }

    public async Task FlushAsync()
    {
        pending?.Cancel();
        await gate.WaitAsync();
        try
        {
            while (HasPending)
            {
                long savingRevision = revision;
                var savingSnapshot = snapshot;
                await save(savingSnapshot);
                savedRevision = savingRevision;
                if (!HasPending) saved();
            }
        }
        finally { gate.Release(); }
    }
}
