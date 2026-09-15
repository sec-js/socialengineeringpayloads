/**
 * Supply Chain Attack - Educational Demonstration
 * =================================================
 * DISCLAIMER: Educational purposes ONLY. Do not use without authorization.
 * 
 * This file demonstrates what malicious preinstall scripts look like
 * so security teams can build detection rules and awareness.
 * 
 * This PoC version only demonstrates the STRUCTURE — it does NOT
 * exfiltrate data, it only logs what WOULD be captured.
 * 
 * Real supply chain attacks have used similar patterns to:
 * - Steal environment variables (API keys, secrets)
 * - Read .npmrc, .ssh, .aws credentials
 * - Send data to attacker-controlled servers
 * 
 * DETECTION:
 * - Inspect all preinstall/postinstall scripts before npm install
 * - Use npm audit and SCA tools in CI/CD pipeline
 * - Monitor npm install processes for network connections
 * - Pin dependencies with exact hashes in lock files
 */

'use strict';

// === EDUCATIONAL DEMONSTRATION ===
// The following shows what malicious packages collect (for detection awareness)

function demonstrateMaliciousPatterns() {
  console.log('[DEMO] Malicious NPM Package - Educational Reference');
  console.log('[DEMO] This is what real supply chain attacks look for:\n');

  // Pattern 1: Environment variable enumeration
  // Real attackers look for: AWS keys, API tokens, secrets
  const sensitiveEnvPatterns = [
    'AWS_ACCESS_KEY', 'AWS_SECRET',
    'GITHUB_TOKEN', 'NPM_TOKEN',
    'DATABASE_URL', 'SECRET_KEY',
    'API_KEY', 'PRIVATE_KEY'
  ];
  
  console.log('[DEMO] Sensitive env vars an attacker would look for:');
  sensitiveEnvPatterns.forEach(key => {
    const found = process.env[key] ? '[FOUND - would be exfiltrated]' : '[not present]';
    console.log(`  ${key}: ${found}`);
  });

  // Pattern 2: File system access
  // Real attackers read credential files
  const credentialFiles = [
    '~/.npmrc',
    '~/.ssh/id_rsa',
    '~/.aws/credentials',
    '~/.config/gcloud/credentials',
  ];
  
  console.log('\n[DEMO] Files an attacker would try to read:');
  credentialFiles.forEach(file => {
    console.log(`  ${file}: [would attempt to read and exfiltrate]`);
  });

  // Pattern 3: Network exfiltration
  // Real attackers send collected data to C2
  console.log('\n[DEMO] Exfiltration - real attack would send to:');
  console.log('  HTTPS POST to: https://attacker.example.com/collect');
  console.log('  DNS: data.attacker.example.com');
  
  console.log('\n[DEMO] PoC action (safe): launching calc.exe as benign demonstration');
  
  // PoC action: launch calculator (benign, repository convention)
  try {
    const { execSync } = require('child_process');
    // Only execute on Windows (where calc.exe exists)
    if (process.platform === 'win32') {
      console.log('[DEMO] Executing calc.exe as PoC (Windows)');
      // execSync('calc.exe');  // Uncomment for actual PoC testing
    } else {
      console.log(`[DEMO] Platform: ${process.platform} - would execute equivalent PoC`);
    }
  } catch (e) {
    // Ignore errors
  }
  
  console.log('\n[DEMO] ========= DETECTION CHECKLIST =========');
  console.log('[DEMO] ✓ Did this script run automatically on npm install?');
  console.log('[DEMO] ✓ Check if it made network connections');
  console.log('[DEMO] ✓ Check if it read files outside the package dir');
  console.log('[DEMO] ✓ Use "npm pack" to inspect before install');
  console.log('[DEMO] ✓ Use "npm audit" for known malicious packages');
}

// Entry point - simulates preinstall execution
demonstrateMaliciousPatterns();
