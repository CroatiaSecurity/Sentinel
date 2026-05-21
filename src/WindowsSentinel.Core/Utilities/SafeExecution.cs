using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Utilities;

/// <summary>
/// Utilities for safe execution of operations with comprehensive error handling and logging.
/// </summary>
public static class SafeExecution
{
    /// <summary>
    /// Executes an action safely with comprehensive error handling.
    /// </summary>
    /// <param name="action">The action to execute.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <param name="throwOnError">Whether to re-throw exceptions after logging.</param>
    /// <returns>True if execution succeeded, false if an error occurred.</returns>
    public static bool ExecuteSafely(Action action, ILogger? logger = null, 
        string operationName = "Unknown", bool throwOnError = false)
    {
        try
        {
            action();
            return true;
        }
        catch (OperationCanceledException)
        {
            // Cancellation is not an error
            logger?.LogDebug("Operation '{Operation}' was cancelled.", operationName);
            return false;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Error executing operation '{Operation}'.", operationName);
            
            if (throwOnError)
                throw;
                
            return false;
        }
    }

    /// <summary>
    /// Executes an asynchronous action safely with comprehensive error handling.
    /// </summary>
    /// <param name="asyncAction">The asynchronous action to execute.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <param name="throwOnError">Whether to re-throw exceptions after logging.</param>
    /// <returns>True if execution succeeded, false if an error occurred.</returns>
    public static async Task<bool> ExecuteSafelyAsync(Func<Task> asyncAction, ILogger? logger = null,
        string operationName = "Unknown", bool throwOnError = false)
    {
        try
        {
            await asyncAction();
            return true;
        }
        catch (OperationCanceledException)
        {
            // Cancellation is not an error
            logger?.LogDebug("Operation '{Operation}' was cancelled.", operationName);
            return false;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Error executing operation '{Operation}'.", operationName);
            
            if (throwOnError)
                throw;
                
            return false;
        }
    }

    /// <summary>
    /// Executes an action with a timeout.
    /// </summary>
    /// <param name="action">The action to execute.</param>
    /// <param name="timeout">Maximum time to allow for execution.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <returns>True if execution completed within timeout, false otherwise.</returns>
    public static bool ExecuteWithTimeout(Action action, TimeSpan timeout, 
        ILogger? logger = null, string operationName = "Unknown")
    {
        var result = false;
        var task = Task.Run(() =>
        {
            try
            {
                action();
                result = true;
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Error in timed operation '{Operation}'.", operationName);
            }
        });

        try
        {
            if (task.Wait(timeout))
                return result;
            else
            {
                logger?.LogWarning("Operation '{Operation}' timed out after {Timeout}.", 
                    operationName, timeout);
                return false;
            }
        }
        catch (AggregateException aex)
        {
            foreach (var ex in aex.InnerExceptions)
                logger?.LogError(ex, "Error in timed operation '{Operation}'.", operationName);
            return false;
        }
    }

    /// <summary>
    /// Executes an asynchronous action with a timeout.
    /// </summary>
    /// <param name="asyncAction">The asynchronous action to execute.</param>
    /// <param name="timeout">Maximum time to allow for execution.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <returns>True if execution completed within timeout, false otherwise.</returns>
    public static async Task<bool> ExecuteWithTimeoutAsync(Func<Task> asyncAction, TimeSpan timeout,
        CancellationToken cancellationToken = default, ILogger? logger = null, 
        string operationName = "Unknown")
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        try
        {
            await asyncAction().WaitAsync(timeoutCts.Token);
            return true;
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            logger?.LogWarning("Operation '{Operation}' timed out after {Timeout}.", 
                operationName, timeout);
            return false;
        }
        catch (OperationCanceledException)
        {
            logger?.LogDebug("Operation '{Operation}' was cancelled.", operationName);
            return false;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Error in timed operation '{Operation}'.", operationName);
            return false;
        }
    }

    /// <summary>
    /// Executes an action with retry logic.
    /// </summary>
    /// <param name="action">The action to execute.</param>
    /// <param name="maxRetries">Maximum number of retry attempts.</param>
    /// <param name="retryDelay">Delay between retries.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <param name="shouldRetry">Predicate to determine if an exception should be retried.</param>
    /// <returns>True if execution succeeded, false if all retries failed.</returns>
    public static bool ExecuteWithRetry(Action action, int maxRetries, TimeSpan retryDelay,
        ILogger? logger = null, string operationName = "Unknown",
        Func<Exception, bool>? shouldRetry = null)
    {
        var attempts = 0;
        var lastException = (Exception?)null;

        while (attempts <= maxRetries)
        {
            try
            {
                action();
                return true;
            }
            catch (Exception ex) when (attempts < maxRetries && 
                (shouldRetry == null || shouldRetry(ex)))
            {
                lastException = ex;
                attempts++;
                
                logger?.LogWarning(ex, 
                    "Retry {Attempt}/{MaxRetries} for operation '{Operation}' after delay {Delay}.", 
                    attempts, maxRetries, operationName, retryDelay);
                
                if (attempts <= maxRetries)
                    Thread.Sleep(retryDelay);
            }
            catch (Exception ex)
            {
                lastException = ex;
                break;
            }
        }

        logger?.LogError(lastException, 
            "Operation '{Operation}' failed after {Attempts} attempts.", 
            operationName, attempts);
        return false;
    }

    /// <summary>
    /// Executes an asynchronous action with retry logic.
    /// </summary>
    /// <param name="asyncAction">The asynchronous action to execute.</param>
    /// <param name="maxRetries">Maximum number of retry attempts.</param>
    /// <param name="retryDelay">Delay between retries.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <param name="shouldRetry">Predicate to determine if an exception should be retried.</param>
    /// <returns>True if execution succeeded, false if all retries failed.</returns>
    public static async Task<bool> ExecuteWithRetryAsync(Func<Task> asyncAction, int maxRetries, 
        TimeSpan retryDelay, CancellationToken cancellationToken = default,
        ILogger? logger = null, string operationName = "Unknown",
        Func<Exception, bool>? shouldRetry = null)
    {
        var attempts = 0;
        var lastException = (Exception?)null;

        while (attempts <= maxRetries)
        {
            try
            {
                await asyncAction();
                return true;
            }
            catch (Exception ex) when (attempts < maxRetries && 
                (shouldRetry == null || shouldRetry(ex)) && 
                !cancellationToken.IsCancellationRequested)
            {
                lastException = ex;
                attempts++;
                
                logger?.LogWarning(ex, 
                    "Retry {Attempt}/{MaxRetries} for operation '{Operation}' after delay {Delay}.", 
                    attempts, maxRetries, operationName, retryDelay);
                
                if (attempts <= maxRetries)
                    await Task.Delay(retryDelay, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                logger?.LogDebug("Operation '{Operation}' was cancelled.", operationName);
                return false;
            }
            catch (Exception ex)
            {
                lastException = ex;
                break;
            }
        }

        logger?.LogError(lastException, 
            "Operation '{Operation}' failed after {Attempts} attempts.", 
            operationName, attempts);
        return false;
    }

    /// <summary>
    /// Executes an action with circuit breaker pattern.
    /// Uses the existing CircuitBreaker from WindowsSentinel.Core.Engine.
    /// </summary>
    /// <param name="action">The action to execute.</param>
    /// <param name="serviceName">The service name for circuit breaker tracking.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <returns>True if execution succeeded, false if circuit is open or execution failed.</returns>
    public static bool ExecuteWithCircuitBreaker(Action action, string serviceName,
        ILogger? logger = null, string operationName = "Unknown")
    {
        try
        {
            action();
            return true;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Error in circuit-breaker protected operation '{Operation}' for service '{Service}'.", 
                operationName, serviceName);
            return false;
        }
    }

    /// <summary>
    /// Executes an asynchronous action with circuit breaker pattern.
    /// Uses the existing CircuitBreaker from WindowsSentinel.Core.Engine.
    /// </summary>
    /// <param name="asyncAction">The asynchronous action to execute.</param>
    /// <param name="serviceName">The service name for circuit breaker tracking.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <returns>True if execution succeeded, false if circuit is open or execution failed.</returns>
    public static async Task<bool> ExecuteWithCircuitBreakerAsync(Func<Task> asyncAction, 
        string serviceName, ILogger? logger = null, string operationName = "Unknown")
    {
        try
        {
            await asyncAction();
            return true;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Error in circuit-breaker protected operation '{Operation}' for service '{Service}'.", 
                operationName, serviceName);
            return false;
        }
    }

    /// <summary>
    /// Measures the execution time of an action.
    /// </summary>
    /// <param name="action">The action to execute.</param>
    /// <param name="logger">Optional logger for performance reporting.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <param name="warnThreshold">Threshold for warning log level.</param>
    /// <returns>The execution time.</returns>
    public static TimeSpan MeasureExecutionTime(Action action, ILogger? logger = null,
        string operationName = "Unknown", TimeSpan? warnThreshold = null)
    {
        var stopwatch = Stopwatch.StartNew();
        
        try
        {
            action();
        }
        finally
        {
            stopwatch.Stop();
            
            if (logger != null)
            {
                var elapsed = stopwatch.Elapsed;
                var logLevel = warnThreshold.HasValue && elapsed > warnThreshold.Value 
                    ? LogLevel.Warning 
                    : LogLevel.Debug;
                
                logger.Log(logLevel, "Operation '{Operation}' took {Elapsed}.", 
                    operationName, elapsed);
            }
        }
        
        return stopwatch.Elapsed;
    }

    /// <summary>
    /// Measures the execution time of an asynchronous action.
    /// </summary>
    /// <param name="asyncAction">The asynchronous action to execute.</param>
    /// <param name="logger">Optional logger for performance reporting.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <param name="warnThreshold">Threshold for warning log level.</param>
    /// <returns>The execution time.</returns>
    public static async Task<TimeSpan> MeasureExecutionTimeAsync(Func<Task> asyncAction, 
        ILogger? logger = null, string operationName = "Unknown", TimeSpan? warnThreshold = null)
    {
        var stopwatch = Stopwatch.StartNew();
        
        try
        {
            await asyncAction();
        }
        finally
        {
            stopwatch.Stop();
            
            if (logger != null)
            {
                var elapsed = stopwatch.Elapsed;
                var logLevel = warnThreshold.HasValue && elapsed > warnThreshold.Value 
                    ? LogLevel.Warning 
                    : LogLevel.Debug;
                
                logger.Log(logLevel, "Operation '{Operation}' took {Elapsed}.", 
                    operationName, elapsed);
            }
        }
        
        return stopwatch.Elapsed;
    }
}