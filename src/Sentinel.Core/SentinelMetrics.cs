using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Core
{
    public class SentinelMetrics
    {
        private readonly ConcurrentQueue<double> _detectionLatencies = new();
        private readonly ConcurrentQueue<double> _responseLatencies = new();
        private int _falsePositivesCount;
        private int _detectionsCount;
        private int _responsesCount;

        public void RecordDetection(double latencyMs)
        {
            System.Threading.Interlocked.Increment(ref _detectionsCount);
            _detectionLatencies.Enqueue(latencyMs);
            TrimQueue(_detectionLatencies);
        }

        public void RecordResponse(double latencyMs)
        {
            System.Threading.Interlocked.Increment(ref _responsesCount);
            _responseLatencies.Enqueue(latencyMs);
            TrimQueue(_responseLatencies);
        }

        public void RecordFalsePositive()
        {
            System.Threading.Interlocked.Increment(ref _falsePositivesCount);
        }

        public (double p50, double p90, double p95, double p99) GetDetectionLatencyPercentiles()
        {
            return CalculatePercentiles(_detectionLatencies.ToList());
        }

        public (double p50, double p90, double p95, double p99) GetResponseLatencyPercentiles()
        {
            return CalculatePercentiles(_responseLatencies.ToList());
        }

        public int GetDetectionsCount() => _detectionsCount;
        public int GetResponsesCount() => _responsesCount;
        public int GetFalsePositivesCount() => _falsePositivesCount;

        private static void TrimQueue(ConcurrentQueue<double> queue)
        {
            // Keep last 1000 records to prevent memory leak
            while (queue.Count > 1000)
            {
                queue.TryDequeue(out _);
            }
        }

        private static (double p50, double p90, double p95, double p99) CalculatePercentiles(List<double> values)
        {
            if (values.Count == 0) return (0, 0, 0, 0);
            values.Sort();

            double p50 = GetPercentile(values, 0.50);
            double p90 = GetPercentile(values, 0.90);
            double p95 = GetPercentile(values, 0.95);
            double p99 = GetPercentile(values, 0.99);

            return (p50, p90, p95, p99);
        }

        private static double GetPercentile(List<double> sortedValues, double percentile)
        {
            int idx = (int)Math.Ceiling(percentile * sortedValues.Count) - 1;
            idx = Math.Max(0, Math.Min(sortedValues.Count - 1, idx));
            return sortedValues[idx];
        }
    }
}
