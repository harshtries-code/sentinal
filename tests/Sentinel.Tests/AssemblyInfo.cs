using Xunit;

// The CPU governor test measures whole-process CPU, which parallel
// tests would pollute. The suite runs in seconds, so serialize it.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
