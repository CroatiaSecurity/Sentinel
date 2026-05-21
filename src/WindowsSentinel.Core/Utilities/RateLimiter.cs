using System;
using System.Threading;

namespace WindowsSentinel.Core.Utilities;

/// <summary>
/// Thread-safe rate limiter for controlling the frequency of operations.
/// </summary>
public sealed class RateLimiter : IDisposable
{
    private readonly SemaphoreSlim _semaphore;
    private readonly int _maxRequests;
    private readonly TimeSpan _timeWindow;
    private readonly object _lock = new();
    private DateTime _windowStart;
    private int _requestsInCurrentWindow;

    /// <summary>
    /// Initializes a new instance of the <see cref="RateLimiter"/> class.
    /// </summary>
    /// <param name="maxRequests">Maximum number of requests allowed in the time window.</param>
    /// <param name="timeWindow">The time window for rate limiting.</param>
    public RateLimiter(int maxRequests, TimeSpan timeWindow)
    {
        if (maxRequests <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxRequests), "Max requests must be positive.");
        if (timeWindow <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(timeWindow), "Time window must be positive.");

        _maxRequests = maxRequests;
        _timeWindow = timeWindow;
        _semaphore = new SemaphoreSlim(1, 1);
        _windowStart = DateTime.UtcNow;
        _requestsInCurrentWindow = 0;
    }

    /// <summary>
    /// Attempts to acquire permission for an operation.
    /// </summary>
    /// <returns>True if the operation is allowed, false if rate limited.</returns>
    public bool TryAcquire()
    {
        return TryAcquireAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Attempts to acquire permission for an operation asynchronously.
    /// </summary>
    /// <returns>True if the operation is allowed, false if rate limited.</returns>
    public async Task<bool> TryAcquireAsync()
    {
        await _semaphore.WaitAsync();
        try
        {
            var now = DateTime.UtcNow;
            
            // Reset window if it has expired
            if (now - _windowStart >= _timeWindow)
            {
                _windowStart = now;
                _requestsInCurrentWindow = 0;
            }

            // Check if we've exceeded the limit
            if (_requestsInCurrentWindow >= _maxRequests)
            {
                return false;
            }

            _requestsInCurrentWindow++;
            return true;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Acquires permission for an operation, waiting if necessary.
    /// </summary>
    /// <param name="timeout">Maximum time to wait for permission.</param>
    /// <returns>True if permission was acquired, false if timeout occurred.</returns>
    public bool Acquire(TimeSpan timeout)
    {
        return AcquireAsync(timeout).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Acquires permission for an operation asynchronously, waiting if necessary.
    /// </summary>
    /// <param name="timeout">Maximum time to wait for permission.</param>
    /// <returns>True if permission was acquired, false if timeout occurred.</returns>
    public async Task<bool> AcquireAsync(TimeSpan timeout)
    {
        var startTime = DateTime.UtcNow;
        
        while (DateTime.UtcNow - startTime < timeout)
        {
            if (await TryAcquireAsync())
                return true;

            // Wait before retrying
            await Task.Delay(TimeSpan.FromMilliseconds(100));
        }

        return false;
    }

    /// <summary>
    /// Gets the current rate limit status.
    /// </summary>
    /// <returns>A tuple containing (currentRequests, maxRequests, timeRemaining).</returns>
    public (int Current, int Max, TimeSpan Remaining) GetStatus()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var windowEnd = _windowStart + _timeWindow;
            var remaining = windowEnd > now ? windowEnd - now : TimeSpan.Zero;
            
            return (_requestsInCurrentWindow, _maxRequests, remaining);
        }
    }

    /// <summary>
    /// Resets the rate limiter to its initial state.
    /// </summary>
    public void Reset()
    {
        lock (_lock)
        {
            _windowStart = DateTime.UtcNow;
            _requestsInCurrentWindow = 0;
        }
    }

    /// <summary>
    /// Disposes the rate limiter resources.
    /// </summary>
    public void Dispose()
    {
        _semaphore.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// A more advanced rate limiter with burst capability.
/// </summary>
public sealed class BurstRateLimiter : IDisposable
{
    private readonly RateLimiter _sustainedLimiter;
    private readonly RateLimiter _burstLimiter;
    private readonly int _burstCapacity;
    private readonly TimeSpan _burstRechargeTime;
    private DateTime _lastBurstRecharge;
    private int _availableBurstTokens;
    private readonly object _lock = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="BurstRateLimiter"/> class.
    /// </summary>
    /// <param name="sustainedRate">Sustained rate (requests per time window).</param>
    /// <param name="sustainedWindow">Sustained rate time window.</param>
    /// <param name="burstCapacity">Maximum burst capacity.</param>
    /// <param name="burstRechargeTime">Time to fully recharge burst tokens.</param>
    public BurstRateLimiter(int sustainedRate, TimeSpan sustainedWindow, 
                           int burstCapacity, TimeSpan burstRechargeTime)
    {
        _sustainedLimiter = new RateLimiter(sustainedRate, sustainedWindow);
        _burstLimiter = new RateLimiter(burstCapacity, TimeSpan.FromMilliseconds(100)); // Quick burst window
        _burstCapacity = burstCapacity;
        _burstRechargeTime = burstRechargeTime;
        _availableBurstTokens = burstCapacity;
        _lastBurstRecharge = DateTime.UtcNow;
    }

    /// <summary>
    /// Attempts to acquire permission for an operation with burst capability.
    /// </summary>
    /// <returns>True if the operation is allowed, false if rate limited.</returns>
    public async Task<bool> TryAcquireAsync()
    {
        // First try sustained rate
        if (await _sustainedLimiter.TryAcquireAsync())
            return true;

        // Recharge burst tokens
        RechargeBurstTokens();

        // Try burst rate
        lock (_lock)
        {
            if (_availableBurstTokens > 0)
            {
                _availableBurstTokens--;
                return true;
            }
        }

        return false;
    }

    private void RechargeBurstTokens()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var timeSinceRecharge = now - _lastBurstRecharge;
            
            if (timeSinceRecharge > _burstRechargeTime)
            {
                // Full recharge
                _availableBurstTokens = _burstCapacity;
                _lastBurstRecharge = now;
            }
            else
            {
                // Partial recharge based on time elapsed
                var rechargeFraction = timeSinceRecharge.TotalMilliseconds / _burstRechargeTime.TotalMilliseconds;
                var tokensToRecharge = (int)(_burstCapacity * rechargeFraction);
                
                if (tokensToRecharge > 0)
                {
                    _availableBurstTokens = Math.Min(_burstCapacity, _availableBurstTokens + tokensToRecharge);
                    _lastBurstRecharge = now;
                }
            }
        }
    }

    /// <summary>
    /// Gets the current burst limiter status.
    /// </summary>
    /// <returns>A tuple containing (availableBurstTokens, burstCapacity, sustainedStatus).</returns>
    public (int AvailableBurst, int BurstCapacity, (int Current, int Max, TimeSpan Remaining) Sustained) GetStatus()
    {
        lock (_lock)
        {
            var sustainedStatus = _sustainedLimiter.GetStatus();
            return (_availableBurstTokens, _burstCapacity, sustainedStatus);
        }
    }

    /// <summary>
    /// Disposes the burst rate limiter resources.
    /// </summary>
    public void Dispose()
    {
        _sustainedLimiter.Dispose();
        _burstLimiter.Dispose();
        GC.SuppressFinalize(this);
    }
}