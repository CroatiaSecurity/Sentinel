using System;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public class RateLimiter : IDisposable
    {
        private readonly int _limit;
        private readonly TimeSpan _window;
        private readonly object _lock = new();
        private int _count;
        private DateTime _windowStart;
        private bool _disposed;

        // Old API (name: limit, window)
        public RateLimiter(int maxRequests, TimeSpan timeWindow)
        {
            _limit = maxRequests;
            _window = timeWindow;
            _windowStart = DateTime.UtcNow;
        }

        // Compatibility overload used by DllUnloadEngine (maxRequests, timeWindow)
        public RateLimiter(int maxRequests, TimeSpan timeWindow, bool dummy) : this(maxRequests, timeWindow) { }

        public bool AllowRequest() => TryAcquire();

        public bool TryAcquire()
        {
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                if (now - _windowStart >= _window)
                {
                    _count = 0;
                    _windowStart = now;
                }

                if (_count < _limit)
                {
                    _count++;
                    return true;
                }
                return false;
            }
        }

        public (int Current, int Max, TimeSpan Remaining) GetStatus()
        {
            lock (_lock)
            {
                var remaining = _window - (DateTime.UtcNow - _windowStart);
                if (remaining < TimeSpan.Zero) remaining = TimeSpan.Zero;
                return (_count, _limit, remaining);
            }
        }

        public void Dispose()
        {
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    public class BurstRateLimiter : IDisposable
    {
        private readonly int _sustainedRate;
        private readonly TimeSpan _sustainedWindow;
        private readonly int _burstCapacity;
        private readonly object _lock = new();
        private int _sustainedCount;
        private int _burstTokens;
        private DateTime _windowStart;
        private DateTime _lastBurstRefill;
        private bool _disposed;

        // Old simple API
        public BurstRateLimiter(double limitPerSecond, double maxBurst)
        {
            _sustainedRate = (int)limitPerSecond;
            _sustainedWindow = TimeSpan.FromSeconds(1);
            _burstCapacity = (int)maxBurst;
            _burstTokens = _burstCapacity;
            _windowStart = DateTime.UtcNow;
            _lastBurstRefill = DateTime.UtcNow;
        }

        // Full API matching DllUnloadEngine
        public BurstRateLimiter(int sustainedRate, TimeSpan sustainedWindow, int burstCapacity, TimeSpan burstRechargeTime)
        {
            _sustainedRate = sustainedRate;
            _sustainedWindow = sustainedWindow;
            _burstCapacity = burstCapacity;
            _burstTokens = burstCapacity;
            _windowStart = DateTime.UtcNow;
            _lastBurstRefill = DateTime.UtcNow;
        }

        public bool AllowRequest() => TryAcquireAsync().GetAwaiter().GetResult();

        public Task<bool> TryAcquireAsync()
        {
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                // Refill burst tokens
                if (now - _lastBurstRefill > _sustainedWindow)
                {
                    _burstTokens = Math.Min(_burstCapacity, _burstTokens + _sustainedRate);
                    _lastBurstRefill = now;
                }
                // Check sustained rate
                if (now - _windowStart >= _sustainedWindow)
                {
                    _sustainedCount = 0;
                    _windowStart = now;
                }
                if (_sustainedCount < _sustainedRate)
                {
                    _sustainedCount++;
                    return Task.FromResult(true);
                }
                // Fall back to burst
                if (_burstTokens > 0)
                {
                    _burstTokens--;
                    return Task.FromResult(true);
                }
                return Task.FromResult(false);
            }
        }

        public (int AvailableBurst, int BurstCapacity, (int Current, int Max, TimeSpan Remaining) Sustained) GetStatus()
        {
            lock (_lock)
            {
                var remaining = _sustainedWindow - (DateTime.UtcNow - _windowStart);
                if (remaining < TimeSpan.Zero) remaining = TimeSpan.Zero;
                return (_burstTokens, _burstCapacity, (_sustainedCount, _sustainedRate, remaining));
            }
        }

        public void Dispose()
        {
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
