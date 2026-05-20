using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Circuit Breaker - Prevents hammering failing APIs/services.
/// Implements the circuit breaker pattern for resilient operations.
/// </summary>
public sealed class CircuitBreaker
{
    private readonly ILogger<CircuitBreaker> _logger;
    private readonly ConcurrentDictionary<string, CircuitStateData> _circuits;
    
    // Configuration
    private readonly int _failureThreshold = 5;
    private readonly TimeSpan _cooldownDuration = TimeSpan.FromMinutes(5);
    private readonly TimeSpan _timeoutMs = TimeSpan.FromSeconds(10);

    public CircuitBreaker(ILogger<CircuitBreaker> logger)
    {
        _logger = logger;
        _circuits = new ConcurrentDictionary<string, CircuitStateData>();
    }

    /// <summary>
    /// Executes an operation with circuit breaker protection.
    /// </summary>
    public async Task<T?> ExecuteAsync<T>(
        string serviceName,
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken = default)
    {
        // Check circuit state
        var state = GetCircuitState(serviceName);
        
        if (state == CircuitState.Open)
        {
            _logger.LogWarning("CircuitBreaker: {Service} circuit is OPEN - skipping request", serviceName);
            return default;
        }

        try
        {
            using var timeoutCts = new CancellationTokenSource(_timeoutMs);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            var result = await operation(linkedCts.Token);
            
            // Success - record it
            RecordSuccess(serviceName);
            
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Failure - record it
            RecordFailure(serviceName, ex);
            throw;
        }
    }

    /// <summary>
    /// Checks if a service is currently available (circuit not open).
    /// </summary>
    public bool IsServiceAvailable(string serviceName)
    {
        return GetCircuitState(serviceName) != CircuitState.Open;
    }

    /// <summary>
    /// Manually resets a circuit.
    /// </summary>
    public void ResetCircuit(string serviceName)
    {
        _circuits.TryRemove(serviceName, out _);
        _logger.LogInformation("CircuitBreaker: {Service} circuit manually reset", serviceName);
    }

    /// <summary>
    /// Gets the status of all circuits.
    /// </summary>
    public Dictionary<string, CircuitStatus> GetAllCircuitStatus()
    {
        return _circuits.ToDictionary(
            kvp => kvp.Key,
            kvp => new CircuitStatus
            {
                State = GetCircuitState(kvp.Key),
                ConsecutiveFailures = kvp.Value.ConsecutiveFailures,
                LastFailureTime = kvp.Value.LastFailureTime,
                TotalFailures = kvp.Value.TotalFailures,
                TotalSuccesses = kvp.Value.TotalSuccesses
            });
    }

    private CircuitState GetCircuitState(string serviceName)
    {
        if (!_circuits.TryGetValue(serviceName, out var state))
        {
            return CircuitState.Closed;
        }

        // Check if cooldown period has passed
        if (state.State == CircuitState.Open)
        {
            if (DateTimeOffset.UtcNow - state.LastFailureTime > _cooldownDuration)
            {
                // Transition to half-open
                state.State = CircuitState.HalfOpen;
                state.ConsecutiveFailures = 0;
                _logger.LogInformation("CircuitBreaker: {Service} transitioned to HALF-OPEN", serviceName);
            }
            else
            {
                return CircuitState.Open;
            }
        }

        return state.State;
    }

    private void RecordSuccess(string serviceName)
    {
        var state = _circuits.GetOrAdd(serviceName, _ => new CircuitStateData());
        
        state.ConsecutiveFailures = 0;
        state.TotalSuccesses++;
        
        // If we were half-open, close the circuit
        if (state.State == CircuitState.HalfOpen)
        {
            state.State = CircuitState.Closed;
            _logger.LogInformation("CircuitBreaker: {Service} circuit CLOSED (recovered)", serviceName);
        }
    }

    private void RecordFailure(string serviceName, Exception ex)
    {
        var state = _circuits.GetOrAdd(serviceName, _ => new CircuitStateData());
        
        state.ConsecutiveFailures++;
        state.TotalFailures++;
        state.LastFailureTime = DateTimeOffset.UtcNow;
        state.LastException = ex.Message;

        // Check if we should open the circuit
        if (state.ConsecutiveFailures >= _failureThreshold)
        {
            state.State = CircuitState.Open;
            _logger.LogError(
                "CircuitBreaker: {Service} circuit OPENED after {Failures} consecutive failures. Last error: {Error}",
                serviceName,
                state.ConsecutiveFailures,
                ex.Message);
        }
    }
}

/// <summary>
/// Circuit state for a service.
/// </summary>
public sealed class CircuitStateData
{
    public CircuitState State { get; set; } = CircuitState.Closed;
    public int ConsecutiveFailures { get; set; } = 0;
    public int TotalFailures { get; set; } = 0;
    public int TotalSuccesses { get; set; } = 0;
    public DateTimeOffset LastFailureTime { get; set; } = DateTimeOffset.MinValue;
    public string? LastException { get; set; }
}

/// <summary>
/// Circuit state enum.
/// </summary>
public enum CircuitState
{
    Closed,     // Normal operation
    Open,       // Failing - requests blocked
    HalfOpen    // Testing if service recovered
}

/// <summary>
/// Circuit status for reporting.
/// </summary>
public sealed class CircuitStatus
{
    public CircuitState State { get; set; }
    public int ConsecutiveFailures { get; set; }
    public DateTimeOffset LastFailureTime { get; set; }
    public int TotalFailures { get; set; }
    public int TotalSuccesses { get; set; }

    public bool IsHealthy => State == CircuitState.Closed;
    public string StatusText => State switch
    {
        CircuitState.Closed => "Healthy",
        CircuitState.Open => "Circuit Open (Failing)",
        CircuitState.HalfOpen => "Testing Recovery",
        _ => "Unknown"
    };
}


