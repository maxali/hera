# Quick Start: Implementing GC Spec Issues

## TL;DR

```bash
# Implement a single issue
/implement-gc-spec 9

# Implement all issues
/implement-gc-spec all

# Check command is available
/help
```

## Your First Implementation

### Step 1: Test with an Easy Issue

Start with Issue #27 (Input Validation) - it's straightforward and self-contained:

```bash
/implement-gc-spec 27
```

**What will happen:**
1. Claude reads GARBAGE_COLLECTION_SPEC.md
2. Claude reads Cloudflare docs via context7
3. Claude implements input validation in `DeleteTunnelByName()`
4. Claude runs `go build` to verify
5. Claude reports success/failure

**Expected output:**
```
✅ Research Phase Complete
   - Read GARBAGE_COLLECTION_SPEC.md issue #27
   - Retrieved cloudflared documentation
   - Identified: hera/tunnel.go needs modification

✅ Implementation Phase Complete
   - Added input validation for tunnel names
   - Added path traversal prevention
   - Added import for strings package

✅ Validation Phase Complete
   - go build: SUCCESS
   - All safety checks present
   - Matches spec lines 343-351

Files modified: hera/tunnel.go
```

### Step 2: Try a More Complex Issue

Issue #9 (Registry Mutex) touches multiple functions:

```bash
/implement-gc-spec 9
```

**What to expect:**
- Longer implementation (3+ functions modified)
- More detailed progress tracking
- Multiple build validations

### Step 3: Full Implementation

When ready, implement everything:

```bash
/implement-gc-spec all
```

**Timeline estimate:** 15-30 minutes for all issues

## What Makes This Command Different?

### Traditional Approach
```
You: "Add mutex to registry"
Claude: *writes code without research*
You: "This doesn't match the spec"
Claude: *rewrites differently*
You: "Still wrong, here's the spec example"
Claude: *finally gets it right*
```

### With /implement-gc-spec
```
You: "/implement-gc-spec 9"
Claude:
  1. Reads Cloudflare docs ✅
  2. Reads spec exact example ✅
  3. Implements exactly as specified ✅
  4. Validates with go build ✅
  5. Reports results ✅
```

**Result:** First implementation is correct.

## Command Flow Diagram

```
┌─────────────────────────────────────────┐
│ /implement-gc-spec [issue-number]      │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│ Phase 1: Research & Planning            │
├─────────────────────────────────────────┤
│ ✓ Read GARBAGE_COLLECTION_SPEC.md       │
│ ✓ Extract issue details & code examples │
│ ✓ Fetch Cloudflare docs (context7)      │
│ ✓ Create TodoWrite checklist            │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│ Phase 2: Read Current Code              │
├─────────────────────────────────────────┤
│ ✓ Read affected files completely        │
│ ✓ Identify integration points           │
│ ✓ Check existing patterns               │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│ Phase 3: Implementation                 │
├─────────────────────────────────────────┤
│ ✓ Copy spec code examples               │
│ ✓ Add required imports                  │
│ ✓ Apply changes to files                │
│ ✓ Preserve existing functionality       │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│ Phase 4: Validation                     │
├─────────────────────────────────────────┤
│ ✓ Run go build                          │
│ ✓ Check for errors                      │
│ ✓ Compare to spec                       │
│ ✓ Verify all safety checks              │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│ Phase 5: Documentation                  │
├─────────────────────────────────────────┤
│ ✓ Update TodoWrite                      │
│ ✓ Generate summary                      │
│ ✓ List modified files                   │
└─────────────────────────────────────────┘
```

## Safety Features Built-In

### Automatic Safety Checks

The command enforces:

✅ **Mutex Protection** - All registry access uses locks
✅ **Panic Recovery** - All goroutines have defer/recover
✅ **Timeouts** - All CLI commands timeout after 30s
✅ **Input Validation** - All user inputs validated
✅ **Error Context** - All errors include debugging info

### Build Validation

Won't mark complete until:
- `go build` succeeds
- No compilation errors
- All imports present

### Spec Compliance

Verifies:
- Code matches spec examples line-by-line
- All safety comments present
- Error handling matches spec

## Common Questions

### Q: Do I need to prepare anything?

**A:** No! The command:
- Reads the spec automatically
- Fetches docs automatically
- Identifies files automatically
- Creates todos automatically

Just run the command and let it work.

### Q: What if I don't have context7 MCP?

**A:** The command will:
1. Try context7 first
2. Fall back to web search if needed
3. Still implement based on spec

The spec examples are comprehensive, so MCP is helpful but not blocking.

### Q: Can I customize the implementation?

**A:** The command follows the spec exactly for consistency. If you need customization:

1. Let command implement the spec version
2. Review the implementation
3. Make manual adjustments after
4. Document why you deviated

This ensures you start from a known-good baseline.

### Q: What if the build fails?

**A:** The command will:
1. Show you the error
2. Attempt to fix (missing imports, typos)
3. Re-run build
4. Report results

You can then:
- Let it retry automatically
- Review and fix manually
- Ask for help

### Q: How do I track progress?

**A:** Use TodoWrite integration:
```bash
# In conversation, todos appear like:
✅ Research Cloudflare documentation
✅ Read GARBAGE_COLLECTION_SPEC.md
⏳ Implement mutex protection
⬜ Validate with go build
⬜ Generate summary
```

### Q: Can I interrupt and resume?

**A:** Yes! The command:
- Tracks progress in TodoWrite
- Can be stopped at any phase
- Resume by running the same issue number again

## Pro Tips

### 1. Start Small
```bash
# Good: Start with standalone issues
/implement-gc-spec 27  # Input validation
/implement-gc-spec 15  # CLI timeout

# Then: Build up to integrated features
/implement-gc-spec 9   # Registry mutex
/implement-gc-spec 2   # Race condition fix
```

### 2. Review Generated Code
```bash
# After implementation, review changes
git diff hera/tunnel.go
git diff hera/listener.go

# Understand what changed
# Verify against spec
```

### 3. Test Incrementally
```bash
# After each issue
cd hera && go build
go test ./...

# Verify no regressions
```

### 4. Use Dry-Run First
```bash
# Implement dry-run support first
/implement-gc-spec 12

# Then test your implementation safely
HERA_GC_DRY_RUN=true docker-compose up
```

### 5. Keep Spec Open
Keep GARBAGE_COLLECTION_SPEC.md open while reviewing:
- Compare generated code to spec examples
- Verify all safety comments included
- Check implementation matches intent

## Example Session

```
You: /implement-gc-spec 9

Claude:
📚 Phase 1: Research & Planning
   Reading GARBAGE_COLLECTION_SPEC.md...
   Found Issue #9: Add thread-safe registry access with sync.RWMutex

   Fetching Cloudflare documentation...
   Retrieved cloudflared tunnel API documentation

   Creating implementation checklist...
   ✓ Research complete

📖 Phase 2: Reading Current Code
   Reading hera/tunnel.go...
   Found registry map at line 16
   Found 3 registry access functions:
   - GetTunnelForHost (line 45)
   - RegisterTunnel (line 52)
   - DeregisterTunnel (line 60)

   ✓ Code analysis complete

⚙️ Phase 3: Implementation
   Adding registryMu sync.RWMutex to package vars...
   Updating GetTunnelForHost with RLock/RUnlock...
   Updating RegisterTunnel with Lock/Unlock...
   Updating DeregisterTunnel with Lock/Unlock...
   Adding sync import...

   ✓ Implementation complete

✅ Phase 4: Validation
   Running: go build...
   Build successful!

   Verifying mutex usage:
   ✓ GetTunnelForHost uses RLock
   ✓ RegisterTunnel uses Lock
   ✓ DeregisterTunnel uses Lock
   ✓ All defers present

   ✓ Validation complete

📝 Phase 5: Documentation
   Summary:
   - Added registryMu sync.RWMutex for thread safety
   - Protected all registry access with locks
   - Follows spec lines 171-223 exactly

   Files modified: hera/tunnel.go

   ✅ Issue #9 implementation complete!

You: Great! Now /implement-gc-spec 15

Claude: [repeats process for Issue #15...]
```

## Next Steps

1. **Try it now:** `/implement-gc-spec 27`
2. **Review output:** Check generated code matches spec
3. **Validate:** Run `go build` manually to verify
4. **Continue:** Pick next issue from recommended order
5. **Complete:** Eventually run `/implement-gc-spec all`

## Getting Help

If you encounter issues:

1. **Check the spec:** GARBAGE_COLLECTION_SPEC.md has detailed examples
2. **Review command:** .claude/commands/implement-gc-spec.md
3. **Read README:** .claude/commands/README.md
4. **Ask Claude:** Describe the specific error/problem

## Ready?

Start your first implementation:

```bash
/implement-gc-spec 27
```

Let the command guide you through the process!

---

**Remember:** The command is designed to do the heavy lifting. Your job is to:
1. Run the command
2. Review the results
3. Verify it matches expectations
4. Move to the next issue

Happy implementing! 🚀
