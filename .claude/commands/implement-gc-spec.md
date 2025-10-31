---
description: Implement GARBAGE_COLLECTION_SPEC.md issues with Cloudflare docs research
argument-hint: [issue-number or "all"]
allowed-tools: Read, Grep, Edit, Write, Bash(go:*), Bash(git:*), TodoWrite, mcp__context7__resolve-library-id, mcp__context7__get-library-docs
model: sonnet
---

# Implement Garbage Collection Spec Issue

You are implementing issues from the GARBAGE_COLLECTION_SPEC.md specification for Hera's orphaned tunnel cleanup system.

## Your Mission

Implement issue **#$ARGUMENTS** from `/Users/gbmoalab/git/test/crossflared/hera/GARBAGE_COLLECTION_SPEC.md` following these strict guidelines:

1. **Read documentation FIRST** - Never implement without understanding Cloudflare tunnel APIs
2. **Follow the spec exactly** - The spec has detailed code examples you must follow
3. **Test your changes** - Verify syntax and logic before completing
4. **Track progress** - Use TodoWrite to show your work

## Step-by-Step Implementation Process

### Phase 1: Research & Planning (MANDATORY)

**Step 1.1: Read the Issue**
- Read `GARBAGE_COLLECTION_SPEC.md` to find issue #$ARGUMENTS
- Identify which files need modification (tunnel.go, listener.go, main.go, etc.)
- Extract the specific code examples provided in the spec
- Understand WHY this fix is needed (safety, performance, correctness)

**Step 1.2: Read Cloudflare Documentation** (CRITICAL - DO NOT SKIP)

Before writing ANY code, you MUST research Cloudflare Tunnel documentation:

```
1. Use context7 MCP to get cloudflared documentation:
   - Call mcp__context7__resolve-library-id with libraryName: "cloudflared"
   - Call mcp__context7__get-library-docs with the library ID
   - Focus on: tunnel lifecycle, JSON output format, CLI commands

2. Pay special attention to:
   - `cloudflared tunnel list --output json` - exact JSON structure
   - `cloudflared tunnel delete` - deletion behavior, idempotency
   - Tunnel states (active, deleted, connections)
   - Error messages and edge cases
```

**Why this matters:** The spec assumes certain JSON structures and behaviors. You must verify these assumptions against official docs before implementing.

**Step 1.3: Create Todo List**

Use TodoWrite to create a checklist for this issue. Example structure:

```
1. Research Cloudflare tunnel documentation
2. Read current implementation of [affected files]
3. Implement [specific change from spec]
4. Verify Go syntax with `go build`
5. Review changes for completeness
```

### Phase 2: Read Current Code

**Step 2.1: Understand Existing Implementation**

Read the files you'll be modifying:
- For tunnel.go changes: Read entire tunnel.go file first
- For listener.go changes: Read entire listener.go file first
- For main.go changes: Read main.go starting from line 35

Look for:
- Existing registry maps and their usage
- Current function signatures
- Import statements (you may need to add new imports)
- Existing error handling patterns

**Step 2.2: Identify Integration Points**

Find where your code will connect:
- If adding mutex protection: locate all registry access points
- If adding new functions: identify where they'll be called
- If modifying structs: check all places structs are used

### Phase 3: Implementation

**Step 3.1: Apply Spec Code Examples**

The spec provides EXACT code examples. Your job is to:

1. **Copy the code structure from the spec** - Don't reinvent, use what's provided
2. **Adapt to existing code style** - Match indentation, naming conventions
3. **Add all required imports** - Check if you need to add: context, sync, time, etc.
4. **Preserve existing functionality** - Don't break working code

**Critical Implementation Rules:**

```go
// ✅ CORRECT - Follow spec exactly
registryMu.RLock()
defer registryMu.RUnlock()

// ❌ WRONG - Don't invent your own approach
// Using channels instead of mutex (unless spec says so)

// ✅ CORRECT - Use spec's error handling
if err != nil {
    log.Warnf("Failed to parse timestamp: %v - SKIPPING for safety", err)
    continue  // Skip, don't ignore
}

// ❌ WRONG - Different error handling
if err != nil {
    log.Warnf("Failed to parse: %v", err)
    // Missing the 'continue' - could bypass safety check!
}
```

**Step 3.2: Implement Required Changes**

Based on the issue number, implement the appropriate changes:

**Issue #4 (Certificate Matching):**
- Modify getAllCertificates() to use FindAllCertificates(l.Fs)
- Add certificate validation loop
- Use getRootDomain logic for matching

**Issue #6 (Panic Recovery):**
- Add defer/recover blocks to all goroutines
- Log panic with context (certificate name, operation)
- Send error results to prevent blocking

**Issue #7 (Timestamp Parsing):**
- Add zero-time check: `raw.CreatedAt != "" && raw.CreatedAt != "0001-01-01T00:00:00Z"`
- Add parsing error handling with `continue`
- Log SKIPPING for safety

**Issue #9 (Registry Mutex):**
- Add `registryMu sync.RWMutex` to package variables
- Update GetTunnelForHost with RLock
- Update RegisterTunnel with Lock
- Update DeregisterTunnel with Lock

**Issue #11 (Concurrency Limit):**
- Add `const maxConcurrency = 20`
- Create semaphore channel
- Acquire/release in goroutine defer

**Issue #12 (Dry-Run Mode):**
- Add `dryRun := os.Getenv("HERA_GC_DRY_RUN") == "true"` checks
- Add conditional deletion logic
- Add [DRY-RUN] logging

**Issue #15 (CLI Timeout):**
- Wrap commands with `context.WithTimeout(context.Background(), 30*time.Second)`
- Check `ctx.Err() == context.DeadlineExceeded`
- Return timeout-specific error messages

**Issue #27 (Input Validation):**
- Add validation for tunnel names: check for `..`, `;&|`$`
- Add validation for certificate paths
- Return errors for invalid inputs

**For "all" argument:**
- Implement ALL issues in sequence
- Update TodoWrite after each issue
- Verify compilation between issues

**Step 3.3: Add Required Imports**

Check and add necessary imports at the top of files:

```go
import (
    "context"     // For timeouts (Issue #15)
    "sync"        // For mutex (Issue #9, #11)
    "time"        // For timestamps (Issue #7, #15)
    "os"          // For env vars (Issue #12)
    "strconv"     // For config parsing (Issue #18)
    "strings"     // For validation (Issue #27)
)
```

### Phase 4: Validation

**Step 4.1: Syntax Check**

Run Go build to check for syntax errors:
```bash
cd hera && go build -o /dev/null ./...
```

If errors occur:
- Read the error message carefully
- Fix the issue
- Re-run the build
- Do NOT mark todo as complete until build succeeds

**Step 4.2: Logic Review**

Verify your implementation:
- [ ] All safety checks present (age, connections, registry, ProcessManager)
- [ ] Mutex protection on all registry access
- [ ] Panic recovery in all goroutines
- [ ] Timeouts on all CLI commands
- [ ] Input validation on user inputs
- [ ] Dry-run mode properly integrated
- [ ] Error messages include context

**Step 4.3: Cross-Reference Spec**

Compare your code to the spec examples:
- Read the spec section for your issue again
- Line-by-line comparison with spec code examples
- Verify you didn't miss any comments or safety checks

### Phase 5: Documentation

**Step 5.1: Update Todo List**

Mark the issue as complete in TodoWrite:
```
✅ Implemented issue #X
```

**Step 5.2: Summary**

Provide a brief summary of what you implemented:
- Which files were modified
- What specific changes were made
- Any deviations from the spec (with justification)
- Build status (success/failure)

## Special Handling for Specific Issues

### Issue #1 (Architecture Mismatch)
**NOT NEEDED** - Already fixed in spec v2.1 (s6 references removed)

### Issue #2 (Race Condition)
Implement the triple-check verification:
1. Re-query Docker containers (lines 576-595 in spec)
2. Check registry with GetTunnelForHost (lines 602-605)
3. Check ProcessManager.IsRunning (line 609)

All three checks must pass before deletion.

### Issue #3 (Registry Check)
This is part of Issue #2's triple-check. Ensure GetTunnelForHost is called in pre-deletion verification.

### Issue #5 (Unsafe Type Assertion)
**OUT OF SCOPE** - This is existing code, not part of GC spec. Skip this issue.

### Issue #10 (Sequential API Calls)
**ALREADY IMPLEMENTED** - Spec v2.0 added parallel processing. No code changes needed.

## Error Handling Guidelines

**When you encounter issues:**

1. **Compilation Errors:**
   - Read error message completely
   - Identify missing imports, typos, or logic errors
   - Fix and re-run `go build`
   - Do NOT proceed until build is clean

2. **Missing Functions:**
   - Check if function exists in codebase with Grep
   - If missing, implement it per spec
   - Example: `processManager.IsRunning()` may need to be added

3. **Spec Ambiguity:**
   - Re-read the spec section carefully
   - Look for code examples in spec (lines 175-725)
   - Check "Background" section (lines 36-100) for context
   - Ask user for clarification if truly ambiguous

4. **Documentation Conflicts:**
   - If Cloudflare docs differ from spec assumptions:
     - Note the discrepancy
     - Follow the Cloudflare official docs
     - Adapt spec code to match reality
     - Document the change in your summary

## Quality Checklist

Before marking issue as complete, verify:

- [ ] Read Cloudflare documentation via context7
- [ ] Read GARBAGE_COLLECTION_SPEC.md for issue details
- [ ] Read current code in affected files
- [ ] Implemented changes match spec code examples
- [ ] Added all required imports
- [ ] Added proper error handling
- [ ] Added safety checks (mutex locks, panic recovery, timeouts)
- [ ] Syntax validated with `go build`
- [ ] TodoWrite updated with progress
- [ ] Summary provided with file changes

## Examples of Good Implementation

### Example 1: Implementing Issue #9 (Registry Mutex)

```
Step 1: Research
- ✅ Read context7 docs for Go sync.RWMutex best practices
- ✅ Read GARBAGE_COLLECTION_SPEC.md lines 171-223
- ✅ Identified that registry is accessed in 3 functions

Step 2: Implementation
- ✅ Added registryMu sync.RWMutex to package vars
- ✅ Updated GetTunnelForHost with RLock/RUnlock
- ✅ Updated RegisterTunnel with Lock/Unlock
- ✅ Updated DeregisterTunnel with Lock/Unlock

Step 3: Validation
- ✅ go build successful
- ✅ All registry accesses protected
- ✅ Follows spec exactly (lines 187-223)

Files modified: hera/tunnel.go
```

### Example 2: Implementing Issue #15 (CLI Timeout)

```
Step 1: Research
- ✅ Read context7 docs for cloudflared CLI behavior
- ✅ Read GARBAGE_COLLECTION_SPEC.md lines 275-290, 353-367
- ✅ Confirmed 30-second timeout is appropriate

Step 2: Implementation
- ✅ Added context.WithTimeout to ListAllCloudflaredTunnels
- ✅ Added context.WithTimeout to DeleteTunnelByName
- ✅ Added DeadlineExceeded error checking
- ✅ Added timeout-specific error messages
- ✅ Added context import

Step 3: Validation
- ✅ go build successful
- ✅ Both functions timeout after 30s
- ✅ Matches spec implementation

Files modified: hera/tunnel.go (added import, modified 2 functions)
```

## Final Reminders

**CRITICAL RULES:**

1. **Documentation First**: Always read Cloudflare docs via context7 before coding
2. **Follow the Spec**: The spec has detailed examples - USE THEM
3. **Safety First**: All safety checks must be present (mutex, panic recovery, timeouts)
4. **Validate**: Run `go build` before marking complete
5. **Track Progress**: Use TodoWrite throughout

**DO NOT:**
- Skip reading documentation
- Invent your own implementation without checking spec
- Remove or skip safety checks
- Mark todo complete without successful build
- Implement without understanding WHY the fix is needed

## Start Implementation Now

Read GARBAGE_COLLECTION_SPEC.md to find issue #$ARGUMENTS, then follow the step-by-step process above.

If $ARGUMENTS is "all", implement issues in this order:
1. #9 (Registry Mutex) - Foundation for thread safety
2. #4 (Certificate Matching) - Core functionality
3. #7 (Timestamp Parsing) - Safety check
4. #6 (Panic Recovery) - Error handling
5. #11 (Concurrency Limit) - Performance
6. #15 (CLI Timeout) - Reliability
7. #12 (Dry-Run Mode) - Testing
8. #27 (Input Validation) - Security
9. #26 (Certificate Validation) - Safety
10. #18 (Age Config Validation) - Configuration
11. #28 (Performance Benchmarks) - Documentation only

Remember: Quality over speed. A well-researched, properly implemented fix is better than a quick, buggy implementation.

Begin!
