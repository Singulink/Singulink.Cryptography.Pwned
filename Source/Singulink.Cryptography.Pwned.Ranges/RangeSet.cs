namespace Singulink.Cryptography.Pwned.Ranges;

/// <summary>
/// A thread-safe set of range prefixes, stored as one bit per prefix.
/// </summary>
internal sealed class RangeSet
{
    private readonly ulong[] _bits;
    private int _count;

    public RangeSet(int capacity)
    {
        Capacity = capacity;
        _bits = new ulong[(capacity + 63) / 64];
    }

    public int Capacity { get; }

    public int Count => Volatile.Read(ref _count);

    public bool Contains(int prefix) => (Volatile.Read(ref _bits[prefix >> 6]) & (1UL << prefix)) is not 0;

    public bool Add(int prefix)
    {
        ulong bit = 1UL << prefix;
        ref ulong word = ref _bits[prefix >> 6];

        if ((Volatile.Read(ref word) & bit) is not 0 || (Interlocked.Or(ref word, bit) & bit) is not 0)
            return false;

        Interlocked.Increment(ref _count);
        return true;
    }

    public bool Remove(int prefix)
    {
        ulong bit = 1UL << prefix;
        ref ulong word = ref _bits[prefix >> 6];

        if ((Volatile.Read(ref word) & bit) is 0 || (Interlocked.And(ref word, ~bit) & bit) is 0)
            return false;

        Interlocked.Decrement(ref _count);
        return true;
    }
}
