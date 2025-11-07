# Pelican Logging Synchronicity Verification Report

**Date**: 2025-11-07
**Status**: ✅ CONFIRMED - Pelican logs synchronously

## Executive Summary

This report confirms that **Pelican logs synchronously**, meaning each log write blocks the calling goroutine until the I/O operation completes. This behavior has performance implications, especially when:
1. Log files are on slow storage
2. Mutexes are held while logging (blocking other goroutines)

## 1. Logging Implementation Analysis

### 1.1 Logging Library
- **Library**: `github.com/sirupsen/logrus v1.9.3`
- **Key Files**:
  - `/home/user/pelican/logging/logging.go` - Core buffering and flush logic
  - `/home/user/pelican/config/logging.go` - Configuration and filtering

### 1.2 Logging Flow

#### Phase 1: Buffering (Before FlushLogs)
When Pelican starts, logging is buffered in memory:

```go
// logging/logging.go:163-176
func SetupLogBuffering() {
    log.SetOutput(io.Discard)  // Discard logs initially
    hook := NewBufferedLogHook()
    log.AddHook(hook)
}
```

The `BufferedLogHook` stores log entries in memory (`hook.entries`) without writing to disk.

#### Phase 2: Transition (FlushLogs Called)
`FlushLogs()` is called after configuration is loaded:

```go
// logging/logging.go:83-151
func FlushLogs(pushToFile bool) {
    flushOnce.Do(func() {
        // 1. Open log file (if configured)
        if pushToFile && logLocation != "" {
            f, err := os.OpenFile(logLocation, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
            log.SetOutput(f)
        } else {
            log.SetOutput(os.Stderr)
        }

        // 2. Flush buffered logs SYNCHRONOUSLY
        for _, entry := range hook.entries {
            formatted, err := entry.String()
            if err == nil {
                _, _ = log.StandardLogger().Out.Write([]byte(formatted))  // BLOCKING WRITE
            }
        }

        // 3. Sync to disk
        if out, ok := log.StandardLogger().Out.(*os.File); ok {
            _ = out.Sync()  // FSYNC - forces write to disk
        }

        // 4. Remove buffering hook
        removeBufferedHook()
    })
}
```

#### Phase 3: Direct Logging (After FlushLogs)
After `FlushLogs()` completes, the `BufferedLogHook` is removed. All subsequent log calls write **directly and synchronously** through logrus to the configured output (file or stderr).

### 1.3 Logrus Synchronous Behavior

Logrus performs synchronous writes through its `Logger.Out` io.Writer:

1. **Entry Creation**: `log.Debug()`, `log.Info()`, etc. create a `log.Entry`
2. **Formatter**: Entry is formatted to string
3. **Write**: `entry.Logger.Out.Write([]byte)` is called - **THIS IS A BLOCKING I/O CALL**
4. **Return**: Control returns to caller only after write completes

**Key Evidence:**
- Line 138 in `logging.go`: `log.StandardLogger().Out.Write([]byte(formatted))`
- This directly calls `os.File.Write()` or `os.Stderr.Write()`
- Both are **blocking system calls** that wait for kernel I/O completion

### 1.4 No Async Buffering
Logrus does NOT implement:
- Background writer goroutines
- Asynchronous channels for log queueing
- Write-behind caching

Every log statement waits for the complete write operation, including:
- Kernel buffer copy
- Potential disk I/O (if file is unbuffered or cache is full)
- File system metadata updates

## 2. Performance Impact

### 2.1 Slow Storage Impact
If the log file is on slow storage (e.g., network filesystem, slow disk):

1. **Direct Latency**: Each `log.Info()` call blocks for ~1-100ms (depending on storage)
2. **Cascading Delays**: If 10 logs are written sequentially, that's 10-1000ms of blocking time
3. **Goroutine Starvation**: Other goroutines cannot progress if they're waiting for the same lock

### 2.2 Mutex Contention Amplification
When code holds a mutex and logs, the lock is held **for the duration of the I/O operation**:

```go
mu.Lock()
// ... do work ...
log.Info("Status update")  // Blocks for I/O, lock still held!
mu.Unlock()
```

This means:
- Other goroutines waiting on `mu` are blocked longer
- Throughput decreases proportionally to log I/O latency
- System becomes less responsive under load

## 3. Identified Cases: Mutexes Held While Logging

### Summary Statistics
- **Total Instances Found**: 13
- **Files Affected**: 5
- **Risk Levels**:
  - HIGH: 3 instances (multiple logs under critical lock)
  - MODERATE: 7 instances (conditional logging under lock)
  - LOW: 3 instances (short critical sections)

---

### 3.1 HIGH RISK Cases

#### Case 1: director/director_api.go:114-127
**Lock**: `statUtilsMutex` (protects `statUtils` map)
**Issue**: Multiple log statements while locked

```go
statUtilsMutex.Lock()
defer statUtilsMutex.Unlock()
statUtil, ok := statUtils[serverUrl]
if ok {
    statUtil.Cancel()
    if err := statUtil.Errgroup.Wait(); err != nil {
        log.Info(fmt.Sprintf("...error: %v", err))  // LINE 120 - BLOCKING LOG
    }
    delete(statUtils, serverUrl)
    log.Debugf("Stat util for %s server %s is deleted.", ...)  // LINE 123 - BLOCKING LOG
    statUtil.ResultCache.DeleteAll()
    statUtil.ResultCache.Stop()
} else {
    log.Debugf("Stat util not found...")  // LINE 127 - BLOCKING LOG
}
```

**Impact**: Any goroutine trying to access `statUtils` must wait for:
- `statUtil.Errgroup.Wait()` to complete
- All log I/O operations to finish
- Cache cleanup operations

**Recommended Fix**:
```go
// Capture data under lock
statUtilsMutex.Lock()
statUtil, ok := statUtils[serverUrl]
if ok {
    delete(statUtils, serverUrl)
}
statUtilsMutex.Unlock()

// Perform cleanup and logging WITHOUT lock
if ok {
    statUtil.Cancel()
    if err := statUtil.Errgroup.Wait(); err != nil {
        log.Info(fmt.Sprintf("...error: %v", err))
    }
    log.Debugf("Stat util for %s server %s is deleted.", ...)
    statUtil.ResultCache.DeleteAll()
    statUtil.ResultCache.Stop()
} else {
    log.Debugf("Stat util not found...")
}
```

---

#### Case 2: origin/globus.go:203-220
**Lock**: `globusExportsMutex` (protects `globusExports` map)
**Issue**: Error logging during token refresh while locked

```go
globusExportsMutex.Lock()
defer globusExportsMutex.Unlock()
if exp.Status == GlobusInactive {
    return nil
}
newTok, err := refreshGlobusToken(cid, exp.Token)
if err != nil {
    log.Errorf("Failed to refresh Globus token: %v", err)  // LINE 211 - BLOCKING LOG
    newTok, err = refreshGlobusToken(cid, exp.Token)
    if err != nil {
        log.Errorf("Failed to retry refreshing Globus token: %v", err)  // LINE 214 - BLOCKING LOG
    }
}
```

**Impact**: Token refresh is a network operation. Adding log I/O on top means:
- Lock held during: network call + retry + 2 log writes
- Other goroutines accessing `globusExports` are blocked for ~100ms-1s+

**Recommended Fix**:
```go
// Capture state under lock
globusExportsMutex.Lock()
if exp.Status == GlobusInactive {
    globusExportsMutex.Unlock()
    return nil
}
oldToken := exp.Token
globusExportsMutex.Unlock()

// Perform network operations WITHOUT lock
newTok, err := refreshGlobusToken(cid, oldToken)
if err != nil {
    log.Errorf("Failed to refresh Globus token: %v", err)
    newTok, err = refreshGlobusToken(cid, oldToken)
    if err != nil {
        log.Errorf("Failed to retry: %v", err)
        return err
    }
}

// Update state under lock
globusExportsMutex.Lock()
exp.Token = newTok
globusExportsMutex.Unlock()
```

---

#### Case 3: director/cache_ads.go:302-334
**Lock**: `statUtilsMutex`
**Issue**: Configuration validation logging while locked

```go
statUtilsMutex.Lock()
defer statUtilsMutex.Unlock()
statUtil, ok := statUtils[ad.URL.String()]
if !ok || statUtil.Errgroup == nil {
    concLimit := param.Director_StatConcurrencyLimit.GetInt()
    if concLimit <= 0 {
        log.Warningln("...ignoring value", concLimit, "...")  // LINE 312 - BLOCKING LOG
        concLimit = 100
    }
    cap := param.Director_CachePresenceCapacity.GetInt()
    if cap <= 0 {
        log.Warningln("...ignoring value", cap, "...")  // LINE 322 - BLOCKING LOG
        cap = 100
    }
    // ... more setup ...
}
```

**Impact**: Configuration validation errors block all `statUtils` access

**Recommended Fix**:
```go
// Validate configuration BEFORE acquiring lock
concLimit := param.Director_StatConcurrencyLimit.GetInt()
if concLimit <= 0 {
    log.Warningln("...ignoring value", concLimit, "...")
    concLimit = 100
}
cap := param.Director_CachePresenceCapacity.GetInt()
if cap <= 0 {
    log.Warningln("...ignoring value", cap, "...")
    cap = 100
}

// Acquire lock only for map access
statUtilsMutex.Lock()
defer statUtilsMutex.Unlock()
statUtil, ok := statUtils[ad.URL.String()]
if !ok || statUtil.Errgroup == nil {
    // Use validated concLimit and cap
}
```

---

### 3.2 MODERATE RISK Cases

#### Case 4: director/director_api.go:68-93
**Lock**: `filteredServersMutex.RLock()` (read lock)
**Issue**: Error logging in switch statement

```go
filteredServersMutex.RLock()
defer filteredServersMutex.RUnlock()
status, exists := filteredServers[serverName]
if !exists {
    return false, ""
} else {
    switch status {
    case permFiltered:
        return true, permFiltered
    // ... other cases ...
    default:
        log.Error("Unknown filterType: ", status)  // LINE 90 - BLOCKING LOG
        return false, ""
    }
}
```

**Impact**: Read locks are generally less problematic (multiple readers allowed), but log I/O still adds latency

---

#### Case 5: director/director_api.go:287-294
**Lock**: `filteredServersMutex.Lock()`
**Issue**: Debug logging during configuration load

```go
filteredServersMutex.Lock()
defer filteredServersMutex.Unlock()
if param.Director_FilteredServers.IsSet() {
    for _, sn := range param.Director_FilteredServers.GetStringSlice() {
        filteredServers[sn] = permFiltered
    }
    log.Debugln("Loaded server downtime configuration:", filteredServers)  // LINE 294
}
```

**Impact**: Moderate - only runs during initialization

---

#### Case 6-10: director/cache_ads.go:355-395
Multiple instances in `healthTestUtilsMutex` sections with similar patterns.

---

#### Case 11: origin/globus.go:119-153
**Lock**: `globusExportsMutex.Lock()`
**Issue**: Logging in initialization loop

```go
globusExportsMutex.Lock()
defer globusExportsMutex.Unlock()
for _, esp := range exps {
    // ...
    ok, err := collectionExistsByUUID(esp.GlobusCollectionID)
    if err != nil {
        return errors.Wrapf(err, ...)
    }
    if !ok {
        log.Infof("Globus collection %s is not activated...", ...)  // LINE 135
        globusExports[esp.GlobusCollectionID] = &globusEsp
        continue
    }
}
```

---

### 3.3 Properly Handled Cases

#### Example: director/director_api.go:262-276
This code demonstrates **correct pattern** - log AFTER unlocking:

```go
statUtilsMutex.Lock()
statUtilsEntry, ok := statUtils[ad.Key()]
if ok {
    delete(statUtils, ad.Key())
}
statUtilsMutex.Unlock()  // UNLOCK FIRST

// Log in separate goroutine AFTER unlock
if ok {
    go func() {
        if err := statUtilsEntry.Errgroup.Wait(); err != nil {
            log.Infoln("Error:", err)  // SAFE - no lock held
        }
    }()
}
```

## 4. Recommendations

### 4.1 Immediate Actions
1. **Audit HIGH RISK cases** - Refactor to minimize critical section duration
2. **Move logging outside locks** where possible
3. **Use defer carefully** - Ensure logs aren't in deferred functions that run while locked

### 4.2 Long-term Solutions

#### Option A: Asynchronous Logging
Implement a non-blocking log wrapper:

```go
type AsyncLogger struct {
    logChan chan func()
}

func (a *AsyncLogger) Info(msg string) {
    select {
    case a.logChan <- func() { log.Info(msg) }:
    default:
        // Channel full, drop or handle
    }
}
```

**Pros**: Eliminates blocking
**Cons**: Adds complexity, potential log loss, ordering issues

#### Option B: Reduce Logging Under Locks
- Only log errors AFTER releasing locks
- Use structured logging to batch context capture
- Defer non-critical logs until after unlock

#### Option C: Use Different Log Levels
- Keep `log.Debug()` under locks (disabled in production)
- Move `log.Info/Warn/Error()` outside critical sections

### 4.3 Monitoring
Add metrics to track:
- Lock hold duration (before/after logging changes)
- Log write latency percentiles
- Goroutine wait times on contested locks

## 5. Testing Validation

To empirically verify synchronous behavior:

```go
func TestLoggingSynchronicity(t *testing.T) {
    // Create a slow writer
    slowWriter := &slowWriter{delay: 100 * time.Millisecond}
    log.SetOutput(slowWriter)

    start := time.Now()
    log.Info("test message")
    duration := time.Since(start)

    // Verify it blocked for at least the delay
    assert.True(t, duration >= 100*time.Millisecond)
}

type slowWriter struct {
    delay time.Duration
}

func (s *slowWriter) Write(p []byte) (n int, err error) {
    time.Sleep(s.delay)
    return len(p), nil
}
```

## 6. Conclusion

**Verification Status**: ✅ **CONFIRMED**

Pelican logs **synchronously** through logrus v1.9.3, which performs blocking writes to the configured output stream (`os.File` or `os.Stderr`). This behavior causes:

1. **Direct I/O blocking**: Each log call waits for write completion
2. **Mutex contention**: Locks held during logging extend critical sections
3. **Cascading delays**: Multiple logs under lock amplify the problem

**Primary Concern**: 13 identified cases where mutexes are held while logging, with 3 HIGH RISK cases that should be refactored to improve throughput and reduce goroutine contention.

---

**Report Generated By**: Claude Code Agent
**Codebase**: Pelican (github.com/pelicanplatform/pelican)
**Branch**: claude/verify-pelican-sync-logging-011CUuCFfmDMeGFdyKn8sHTn
