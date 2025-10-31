# Hera Slash Commands

This directory contains custom Claude Code slash commands for the Hera project.

## Available Commands

### `/implement-gc-spec [issue-number | "all"]`

**Purpose:** Implement issues from GARBAGE_COLLECTION_SPEC.md with proper documentation research and validation.

**Usage:**
```bash
# Implement a specific issue
/implement-gc-spec 9

# Implement issue #15 (CLI timeouts)
/implement-gc-spec 15

# Implement all issues in recommended order
/implement-gc-spec all
```

**What it does:**
1. **Reads Cloudflare documentation** via context7 MCP to understand tunnel APIs
2. **Reads the GC spec** to extract exact implementation requirements
3. **Reads current code** to understand integration points
4. **Implements the fix** following spec code examples exactly
5. **Validates with `go build`** to ensure no syntax errors
6. **Tracks progress** with TodoWrite for visibility

**Key Features:**
- 🔍 **Documentation-first approach** - Always reads Cloudflare docs before coding
- 📋 **Follows spec exactly** - Uses provided code examples from spec
- ✅ **Auto-validation** - Runs `go build` to verify syntax
- 📊 **Progress tracking** - Uses TodoWrite to show work
- 🛡️ **Safety-focused** - Enforces all safety checks (mutex, panic recovery, timeouts)

**Implementation Order for "all":**
1. #9 - Registry Mutex (thread safety foundation)
2. #4 - Certificate Matching (core functionality)
3. #7 - Timestamp Parsing (safety check)
4. #6 - Panic Recovery (error handling)
5. #11 - Concurrency Limit (performance)
6. #15 - CLI Timeout (reliability)
7. #12 - Dry-Run Mode (testing)
8. #27 - Input Validation (security)
9. #26 - Certificate Validation (safety)
10. #18 - Age Config Validation (configuration)

**Issues Marked OUT OF SCOPE:**
- #1 - Already fixed in spec v2.1
- #5 - Existing code refactoring
- #10 - Already implemented in spec v2.0

### `/implement-tini-upgrade`

**Purpose:** Implement the tini + native Go process manager upgrade to replace s6-overlay.

**Usage:**
```bash
/implement-tini-upgrade
```

**What it does:**
Migrates Hera from s6-overlay to a tini-based architecture with native Go process management.

## Command Design Principles

All Hera slash commands follow these principles:

1. **Documentation First** - Always read official docs via MCP (Cloudflare, Go stdlib, etc.)
2. **Spec-Driven** - Follow specification documents exactly
3. **Validation Built-In** - Auto-validate with build tools
4. **Progress Tracking** - Use TodoWrite for visibility
5. **Safety First** - Enforce safety checks and error handling
6. **Clear Scope** - Explicit about what's in scope vs out of scope

## MCP Integration

Commands use Model Context Protocol (MCP) servers for documentation:

- **context7** - Fetches up-to-date library documentation
  - `mcp__context7__resolve-library-id` - Find library IDs
  - `mcp__context7__get-library-docs` - Get documentation

Example usage in commands:
```markdown
Call mcp__context7__resolve-library-id with libraryName: "cloudflared"
Call mcp__context7__get-library-docs with the library ID
```

## Allowed Tools

Commands restrict tool usage for safety and focus:

- **Read/Grep/Edit/Write** - File operations
- **Bash(go:\*)** - Go build/test commands only
- **Bash(git:\*)** - Git commands only
- **TodoWrite** - Progress tracking
- **MCP tools** - Documentation access

This prevents accidental damage while allowing necessary operations.

## Tips for Using Commands

### For Individual Issues

Start with simpler issues before complex ones:
```bash
# Easy wins first
/implement-gc-spec 27  # Input validation - straightforward
/implement-gc-spec 15  # CLI timeout - clear implementation

# Then foundational changes
/implement-gc-spec 9   # Registry mutex - touches multiple functions

# Finally complex integrations
/implement-gc-spec 2   # Race condition - multi-layer fix
```

### For Full Implementation

Use the "all" argument for complete implementation:
```bash
/implement-gc-spec all
```

The command will implement issues in the optimal order, validating after each.

### If Build Fails

The command will:
1. Show the build error
2. Attempt to fix common issues (missing imports, typos)
3. Re-run build
4. Report status

You can then:
- Review the error in the output
- Let the command retry
- Manually fix if needed

### Tracking Progress

The command uses TodoWrite to show:
- Current issue being implemented
- Phase (Research → Implementation → Validation)
- Completion status
- Next steps

Check todos with `/list` to see progress.

## Creating New Commands

To create a new Hera command:

1. **Create file** in `.claude/commands/[name].md`
2. **Add frontmatter** with description and allowed-tools
3. **Write clear instructions** following prompt engineering best practices
4. **Test** with a real issue
5. **Document** in this README

Example frontmatter:
```yaml
---
description: Brief description of what command does
argument-hint: [expected arguments]
allowed-tools: Read, Write, Bash(go:*), TodoWrite
model: sonnet
---
```

## Command Development Best Practices

Based on Claude Code documentation and Hera experience:

### 1. Clear Instructions
- Be explicit about each step
- Explain WHY, not just WHAT
- Provide concrete examples

### 2. Tool Restrictions
- Only allow necessary tools
- Use specific Bash patterns: `Bash(go:*)` not `Bash`
- Prevents accidental damage

### 3. Error Handling
- Anticipate common failures
- Provide recovery steps
- Don't mark complete on errors

### 4. Documentation First
- Always read official docs before coding
- Use MCP servers for up-to-date info
- Verify assumptions against reality

### 5. Progress Tracking
- Use TodoWrite throughout
- Mark phases clearly
- Show what's next

### 6. Validation
- Build/test after implementation
- Compare against spec
- Verify all safety checks present

## Troubleshooting

### "Command not found"
- Commands must have `description` in frontmatter
- Check filename matches command name
- Restart Claude Code if recently added

### "Tool not allowed"
- Check `allowed-tools` in frontmatter
- Add required tools to allowed list
- Use specific patterns for Bash commands

### "Build failed"
- Review error message
- Check for missing imports
- Verify syntax matches Go standards
- Compare to spec examples

### "MCP server unavailable"
- Check MCP server configuration
- Verify context7 is installed
- Try alternative documentation sources

## Related Documentation

- `/hera/GARBAGE_COLLECTION_SPEC.md` - GC implementation specification
- `/hera/CLAUDE.md` - Project overview and architecture
- [Claude Code Slash Commands](https://docs.claude.com/en/docs/claude-code/slash-commands)
- [Prompt Engineering Guide](https://docs.claude.com/en/docs/build-with-claude/prompt-engineering)

## Contributing

When adding new commands:

1. Follow existing patterns
2. Document thoroughly
3. Test with real scenarios
4. Update this README
5. Commit to repository (shared with team)

## Future Commands (Proposed)

Potential additions:
- `/validate-gc-spec [issue-number]` - Validate implementation against spec
- `/fix-gc-spec [issue-number]` - Quick-fix known issues
- `/test-gc-spec` - Run GC-specific tests
- `/benchmark-gc` - Performance testing

---

**Last Updated:** October 31, 2025
**Hera Version:** Development (GC implementation in progress)
