@echo off
REM LOLBin Execution Chain - Educational Reference
REM ================================================
REM DISCLAIMER: Educational purposes ONLY. Do not use without authorization.
REM This demonstrates a chained LOLBin execution sequence for detection purposes.
REM PoC payload: calc.exe (Windows Calculator)
REM
REM DETECTION NOTES:
REM - Each step in this chain produces detectable indicators
REM - Security teams should alert on these patterns
REM
REM CHAIN PATTERN:
REM cmd.exe -> certutil (download) -> mshta.exe (execute)
REM OR
REM cmd.exe -> rundll32.exe (proxy execute)
REM OR  
REM cmd.exe -> regsvr32.exe (COM scriptlet)

REM Step 1: Environment variable assembly (obfuscation attempt)
REM Detection: cmd.exe with unusual SET commands followed by variable usage
SET _p1=cal
SET _p2=c
SET _poc=%_p1%%_p2%.exe

REM Step 2: Execute via LOLBin (PoC: calc.exe)
REM Detection: mshta.exe or rundll32.exe spawned from cmd.exe
echo [EDUCATIONAL DEMO] Would execute: %_poc%
echo [EDUCATIONAL DEMO] In a real attack, this would be a malicious payload

REM Step 3: Cleanup (attackers often clean up artifacts)
REM Detection: Del commands targeting recently created files
echo [EDUCATIONAL DEMO] Cleanup would occur here

REM ========================
REM DETECTION OPPORTUNITIES:
REM ========================
REM 1. Environment variable assembly pattern (SET _p1=...; SET _p2=...)
REM 2. Variable concatenation for executable names
REM 3. LOLBin spawned from Office/email client
REM 4. Network connections from LOLBins
REM 5. Short-lived processes immediately after document open

echo [INFO] This is a detection reference file, not a functional payload
echo [INFO] See README.md for full detection guidance
