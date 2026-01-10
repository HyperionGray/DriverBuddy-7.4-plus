# DriverBuddy Examples

```
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    Usage Examples                             ║
    ║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║
    ╚═══════════════════════════════════════════════════════════════╝
```

## Example 1: Basic Driver Analysis (IDA Pro)

```python
# Load a Windows kernel driver in IDA Pro
# Press Ctrl+Alt+D to run DriverBuddy

# Expected Output:
[+] Welcome to Driver Buddy
[+] DriverEntry found at 0x00011000
[+] Driver type detected: WDM
[+] Found DispatchDeviceControl at 0x00011234
[+] Searching for interesting C functions...
[+] Found strcpy with 3 references
    └─ Reference at: 0x00011456
    └─ Reference at: 0x00011789
    └─ Reference at: 0x00011abc
```

## Example 2: IOCTL Decoding

### Manual IOCTL Decoding (IDA Pro)

1. Navigate to a location with an IOCTL constant
2. Highlight the IOCTL value (e.g., `cmp eax, 222004h`)
3. Press `Ctrl+Alt+I`

```
[+] IOCTL: 0x00222004
    Device   : FILE_DEVICE_UNKNOWN (0x0022)
    Function : 0x801
    Method   : METHOD_BUFFERED
    Access   : FILE_ANY_ACCESS
```

### Common IOCTL Patterns

```c
// Example 1: Typical IOCTL handler
if (IoControlCode == 0x222004) {
    // DriverBuddy will identify this
}

// Example 2: Switch statement
switch (IoControlCode) {
    case 0x222004:  // Decoded automatically
    case 0x222008:  // Decoded automatically
    case 0x22200C:  // Decoded automatically
}
```

## Example 3: Finding Vulnerabilities

### Buffer Overflow Detection

```
[+] Searching for dangerous C functions...
[+] Found strcpy with 2 references
    └─ Reference at: 0x00011456 (In function: sub_11400)
[+] Found memcpy with 5 references
    └─ Reference at: 0x00011789
    └─ Reference at: 0x00011abc
```

**Manual Review Required:**
```c
// Check if these calls properly validate buffer sizes
char dest[256];
strcpy(dest, user_input);  // ☠ DANGEROUS if user_input > 256 bytes
```

### Missing ProbeForRead/ProbeForWrite

```
[+] Searching for interesting Windows API functions...
[-] ProbeForRead not found
[-] ProbeForWrite not found
[+] Found memcpy with user-controlled size
```

**This indicates potential vulnerabilities:**
```c
// Missing validation - DANGEROUS
memcpy(kernel_buffer, irp->SystemBuffer, input_length);
```

## Example 4: Ghidra Analysis

```python
# Open driver.sys in Ghidra
# Run DriverBuddy_Ghidra.py from Script Manager

# Expected Output:
╔═══════════════════════════════════════════════════════════════╗
║              DriverBuddy for Ghidra                           ║
║              Windows Kernel Driver Analysis                   ║
║                                                                ║
║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║
╚═══════════════════════════════════════════════════════════════╝
[+] Starting DriverBuddy analysis...
[+] Program: driver.sys
[+] Found DriverEntry at: 00011000
[+] Driver type: WDM
```

## Example 5: Binary Ninja Workflow

```python
# 1. Open driver.sys in Binary Ninja
# 2. Navigate to Plugins → DriverBuddy → Analyze Driver
# 3. Review log output

# Common findings:
[+] Found SeAccessCheck with 1 references
    └─ Reference at: 0x00012345
    
# Action: Review this security check
# Verify it's not bypassable
```

## Example 6: Radare2 Command-Line Analysis

```bash
# Launch with script
r2 -i DriverBuddy_Radare2.py vulnerable_driver.sys

# Or interactive mode
r2 vulnerable_driver.sys
[0x00000000]> aaa
[0x00000000]> #!pipe python3 DriverBuddy_Radare2.py

# Output:
╔═══════════════════════════════════════════════════════════════╗
║              DriverBuddy for Radare2                          ║
║              Windows Kernel Driver Analysis                   ║
║                                                                ║
║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║
╚═══════════════════════════════════════════════════════════════╝
[+] Starting DriverBuddy analysis...
[+] Binary: vulnerable_driver.sys
```

## Example 7: Real-World Case Study

### Scenario: Analyzing a Suspicious Driver

```
Driver: example.sys
Goal: Find potential privilege escalation vectors
```

**Step 1: Run DriverBuddy**
```
[+] Driver type: WDM
[+] Found DispatchDeviceControl at 0x00011234
[+] Found 4 IOCTLs:
    - 0x00222004 (METHOD_BUFFERED, FILE_ANY_ACCESS)
    - 0x00222008 (METHOD_BUFFERED, FILE_ANY_ACCESS)
    - 0x0022200C (METHOD_NEITHER, FILE_ANY_ACCESS)  ☠ HIGH RISK
    - 0x00222010 (METHOD_BUFFERED, FILE_WRITE_ACCESS)
```

**Step 2: Focus on High-Risk IOCTL**
- `METHOD_NEITHER` requires manual buffer handling
- `FILE_ANY_ACCESS` means any user can call it

**Step 3: Review the Handler**
```c
case 0x0022200C:
    // ☠ Direct memory access without ProbeForRead
    user_buffer = irp->UserBuffer;
    kernel_buffer = ExAllocatePool(NonPagedPool, 0x1000);
    memcpy(kernel_buffer, user_buffer, input_length);
    // ☠ Vulnerability: No size validation!
```

## Example 8: IOCTL Fuzzing Preparation

### Extract All IOCTLs for Fuzzing

```python
# Run DriverBuddy on target driver
# Extract IOCTL list from output

ioctls = [
    0x00222004,
    0x00222008,
    0x0022200C,
    0x00222010,
    0x00222014,
]

# Use with your favorite fuzzer
for ioctl in ioctls:
    fuzz_ioctl(ioctl)
```

### Prioritize by Risk

```
High Priority (METHOD_NEITHER):
    ☠  0x0022200C - Direct user buffer access
    
Medium Priority (METHOD_BUFFERED with FILE_ANY_ACCESS):
    ☠  0x00222004 - Check for size validation
    ☠  0x00222008 - Check for integer overflows
    
Low Priority (METHOD_BUFFERED with FILE_WRITE_ACCESS):
    ☠  0x00222010 - Requires elevated privileges
```

## Example 9: WDF Driver Analysis

```
[+] Driver type detected: WDF
[+] Searching for WDF function table...
[+] Found WdfFunctions structure
[+] Labeling WDF function pointers...
    - WdfDriverCreate
    - WdfDeviceCreate
    - WdfIoQueueCreate
    - WdfRequestRetrieveInputBuffer
    - WdfRequestRetrieveOutputBuffer
```

**Benefit:** All WDF calls are now properly labeled in your RE tool

## Example 10: Cross-Platform Verification

```bash
# Step 1: Analyze with IDA Pro
ida64 -A -S"DriverBuddy.py" driver.sys

# Step 2: Verify with Ghidra
ghidra_analyzeHeadless /path/to/project ProjectName \
    -import driver.sys \
    -scriptPath /path/to/scripts \
    -postScript DriverBuddy_Ghidra.py

# Step 3: Quick check with Radare2
r2 -i DriverBuddy_Radare2.py driver.sys

# Compare results across platforms
```

## Example 11: Security Checklist

After running DriverBuddy, verify:

```
☠  [ ] All IOCTLs use METHOD_BUFFERED or METHOD_DIRECT
☠  [ ] METHOD_NEITHER handlers use ProbeForRead/ProbeForWrite
☠  [ ] All buffer copies validate sizes
☠  [ ] strcpy/strcat replaced with safe alternatives
☠  [ ] Input buffers are validated before use
☠  [ ] Access checks (SeAccessCheck) present for privileged operations
☠  [ ] Reference counting balanced (ObReferenceObject/ObDereferenceObject)
☠  [ ] No time-of-check/time-of-use (TOCTOU) issues
```

## Tips and Tricks

### IDA Pro Tips

```python
# Rename suspicious function after review
ida_name.set_name(0x00011234, "VulnerableIOCTLHandler")

# Add comment about vulnerability
idc.set_cmt(0x00011456, "Buffer overflow - no size check", 0)

# Mark as dangerous
ida_kernwin.msg("☠ SECURITY ISSUE at %08x\n" % address)
```

### Ghidra Tips

```python
# Create bookmarks for vulnerabilities
createBookmark(addr, "SECURITY", "Buffer overflow risk")

# Set function signature
setFunctionSignature(func, "NTSTATUS VulnerableHandler(PIRP irp)")
```

### Binary Ninja Tips

```python
# Tag dangerous functions
func.add_tag("security", "buffer-overflow")

# Create highlight
bv.set_comment_at(addr, "☠ DANGEROUS: Unbounded memcpy")
```

```
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║         ☠  Happy Hunting!  ☠                                  ║
    ║                                                                ║
    ╚═══════════════════════════════════════════════════════════════╝
```
