# Execute PowerShell on Mouseover – PowerPoint (PPS)

## Overview

Microsoft PowerPoint supports action settings on shapes and text objects, including the ability to run a program when the cursor hovers over an element (`MouseOver` action). A PowerPoint Show file (`.pps`) opens directly in slideshow mode, immediately exposing any mouseover actions to the victim without requiring them to navigate to the slide in edit mode.

## How it Works

An attacker adds a nearly invisible shape (or a large invisible overlay) to a slide and assigns a **Run Program** action on `MouseOver`. When the victim opens the `.pps` file and moves their mouse across the slide, the PowerPoint engine executes the specified program.

PowerPoint prompts the user with a security warning before executing the action; however, attackers leverage social engineering context (e.g., "hover here to unlock content") to trick users into proceeding.

## PoC

The file `Final Market Report_AZ Presentation World Tour 2015 - Germany.pps` contains a mouseover action on a shape that executes PowerShell.

**To create your own PoC PPS:**

1. Open PowerPoint and insert a shape or text box.
2. Right-click the shape → **Action Settings** → **Mouse Over** tab.
3. Select **Run program** and enter:

   ```
   powershell.exe -windowstyle hidden -command "Start-Process calc.exe"
   ```

4. Save the file as a PowerPoint Show (`.pps` or `.ppsx`).
5. Open the saved file — move your mouse over the shape to trigger the action.

## Social Engineering Context

The filename mimics a legitimate corporate presentation (`Final Market Report`) to motivate the victim to open and interact with the slideshow. The `.pps` extension ensures the file opens in presentation mode immediately.

## MITRE ATT&CK

| Field | Value |
|---|---|
| Technique | T1204.002 – User Execution: Malicious File |
| Tactic | Execution |
| Sub-technique | T1566.001 – Spear Phishing Attachment |
| Platform | Windows |

## Detection

- Monitor `POWERPNT.EXE` spawning `powershell.exe`, `cmd.exe`, or `wscript.exe`.
- Alert on `.pps` / `.ppsx` files with `Run Program` action settings.
- Enable Office macro and action security warnings via Group Policy.

## Mitigation

- Set `DisableRunProgram` via Office Group Policy to prevent action-based execution.
- Open PowerPoint files in Protected View to disable action execution until explicitly enabled.
- Train users to be cautious about opening presentation files from untrusted sources.
