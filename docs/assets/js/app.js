(() => {
  'use strict';

  const STORAGE_KEYS = {
    bookmarks: 'sep-bookmarks',
    theme: 'sep-theme'
  };

  const FALLBACK_PAYLOADS = [
  {
    "id": "dde-csv",
    "name": "DDE CSV Payload",
    "category": "DDE Attack",
    "description": "A crafted CSV file that abuses Dynamic Data Exchange formulas to launch commands when opened in Excel.",
    "fullDescription": "This sample places a DDE formula inside a CSV document so Microsoft Excel resolves the field as an external command invocation instead of passive data. When the victim clicks through the security prompt, Excel can spawn a script interpreter or PowerShell child process on the workstation.",
    "targetApplications": [
      "Excel",
      "Windows"
    ],
    "attackVector": "Phishing attachment delivered as a spreadsheet-like CSV file that prompts DDE execution in Excel.",
    "difficultyLevel": 2,
    "detectionDifficulty": 3,
    "techniques": [
      "T1204.002 - Malicious File",
      "T1059.001 - PowerShell",
      "T1566.001 - Spearphishing Attachment"
    ],
    "mitigation": "Disable or restrict DDE in Office where possible and block unexpected child processes from Excel. Train users to reject Office execution prompts and inspect unusual CSV attachments.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/DDE%20based%20social%20engineering%20csv%20payload",
    "status": "Detected",
    "tags": [
      "csv",
      "excel",
      "dde",
      "office",
      "phishing"
    ]
  },
  {
    "id": "dde-doc",
    "name": "DDE DOC Payload",
    "category": "DDE Attack",
    "description": "A weaponized Word document that uses DDE fields to trigger code execution without traditional macros.",
    "fullDescription": "The document embeds a DDEAUTO field that can instruct Microsoft Word to call command interpreters when the file is opened or fields are updated. Because the technique avoids VBA macros, it can slip past controls that only focus on macro-enabled documents.",
    "targetApplications": [
      "Word",
      "Windows"
    ],
    "attackVector": "Malicious Word attachment relying on DDE field updates and user confirmation dialogs.",
    "difficultyLevel": 3,
    "detectionDifficulty": 4,
    "techniques": [
      "T1204.002 - Malicious File",
      "T1059.003 - Windows Command Shell",
      "T1566.001 - Spearphishing Attachment"
    ],
    "mitigation": "Disable automatic field updates and enforce Office Protected View for internet-origin documents. Detect Word spawning script engines, shells, or LOLBins.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/DDE%20based%20social%20engineering%20docx%20payload",
    "status": "Detected",
    "tags": [
      "word",
      "dde",
      "document",
      "office",
      "phishing"
    ]
  },
  {
    "id": "dde-msg",
    "name": "DDE Outlook Message Payload",
    "category": "DDE Attack",
    "description": "An Outlook MSG lure designed to socially engineer the victim into opening a DDE-based Office workflow.",
    "fullDescription": "This payload packages the lure inside an Outlook message file so the attacker controls the email body, subject, and attachment context offline. The message is meant to lower suspicion and steer the victim toward a DDE-enabled document or command prompt flow that continues execution outside Outlook.",
    "targetApplications": [
      "Outlook",
      "Windows"
    ],
    "attackVector": "Saved Outlook message attachment that stages a believable spear-phishing scenario for DDE execution.",
    "difficultyLevel": 2,
    "detectionDifficulty": 3,
    "techniques": [
      "T1566.001 - Spearphishing Attachment",
      "T1204.001 - Malicious Link",
      "T1204.002 - Malicious File"
    ],
    "mitigation": "Treat MSG files as active content in mail controls and sandbox them before delivery. Flag messages that instruct users to bypass Office security prompts.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/DDE%20based%20social%20engineering%20msg%20%28OUTLOOK%29%20payload",
    "status": "Active",
    "tags": [
      "outlook",
      "msg",
      "dde",
      "email",
      "lure"
    ]
  },
  {
    "id": "dde-slk",
    "name": "DDE SLK Payload",
    "category": "DDE Attack",
    "description": "A Symbolic Link spreadsheet file that embeds DDE content to execute commands through Excel.",
    "fullDescription": "SYLK files are plain-text spreadsheet artifacts that Excel still supports and can interpret as formulas or external references. Attackers use the uncommon format to hide DDE behavior in a file type many defenders and end users rarely inspect closely.",
    "targetApplications": [
      "Excel",
      "Windows"
    ],
    "attackVector": "Spear-phishing attachment using an uncommon spreadsheet format to deliver DDE formulas.",
    "difficultyLevel": 3,
    "detectionDifficulty": 4,
    "techniques": [
      "T1204.002 - Malicious File",
      "T1059.003 - Windows Command Shell",
      "T1566.001 - Spearphishing Attachment"
    ],
    "mitigation": "Block or warn on legacy Office file formats such as SYLK from untrusted sources. Monitor Excel launching shells or scripting engines immediately after file open.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/DDE%20based%20social%20engineering%20slk%20payload",
    "status": "Detected",
    "tags": [
      "slk",
      "sylk",
      "excel",
      "dde",
      "legacy-format"
    ]
  },
  {
    "id": "dde-xls",
    "name": "DDE XLS Payload",
    "category": "DDE Attack",
    "description": "A legacy Excel workbook that relies on DDE formulas to execute code after the victim opens the sheet.",
    "fullDescription": "The workbook packages DDE formula abuse in a classic XLS container that fits common business workflows and reduces suspicion. Once the victim accepts the warning dialogs, Excel can chain into command execution and post-exploitation tooling.",
    "targetApplications": [
      "Excel",
      "Windows"
    ],
    "attackVector": "Legacy XLS attachment delivered through phishing and opened in Microsoft Excel.",
    "difficultyLevel": 2,
    "detectionDifficulty": 3,
    "techniques": [
      "T1204.002 - Malicious File",
      "T1059.001 - PowerShell",
      "T1566.001 - Spearphishing Attachment"
    ],
    "mitigation": "Block internet-delivered legacy Office documents unless explicitly allowed. Use application control to stop Excel from launching PowerShell, cmd.exe, or mshta.exe.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/DDE%20based%20social%20engineering%20xls%20payload",
    "status": "Detected",
    "tags": [
      "xls",
      "excel",
      "dde",
      "legacy-office",
      "execution"
    ]
  },
  {
    "id": "embedded-object-scenario1",
    "name": "Embedded Object Scenario 1",
    "category": "Document Execution",
    "description": "A DOCX lure paired with a BAT file to demonstrate embedded-object assisted execution from Office content.",
    "fullDescription": "This scenario uses a convincing Word document as the decoy while a companion batch file provides the actual execution path after the victim interacts with the embedded content. It models attacks where Office documents are used to disguise secondary executables or scripts as supporting material.",
    "targetApplications": [
      "Word",
      "Windows"
    ],
    "attackVector": "Office document plus embedded or adjacent script object that persuades the victim to launch a BAT payload.",
    "difficultyLevel": 3,
    "detectionDifficulty": 2,
    "techniques": [
      "T1204.002 - Malicious File",
      "T1059.003 - Windows Command Shell",
      "T1566.001 - Spearphishing Attachment"
    ],
    "mitigation": "Prevent Office documents from packaging or launching scriptable companion files and scan archives for mixed document-executable bundles. Warn users when documents reference or extract batch files.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/Embedding%20Object%20in%20office%20document/Scenario1",
    "status": "Mitigated",
    "tags": [
      "embedded-object",
      "docx",
      "bat",
      "word",
      "office"
    ]
  },
  {
    "id": "embedded-object-scenario2",
    "name": "Embedded Object Scenario 2",
    "category": "Document Execution",
    "description": "A KPI-themed DOCX lure that chains into a disguised shortcut to trigger local execution.",
    "fullDescription": "The scenario mixes a business-themed Word document with a shortcut file named to resemble a benign calculator or helper component. It demonstrates how attackers combine iconography, file naming, and embedded content to mask Windows shortcut execution behind normal document review activity.",
    "targetApplications": [
      "Word",
      "Windows"
    ],
    "attackVector": "Shortcut-backed object embedded or delivered alongside a Word document to induce the victim to launch a LNK file.",
    "difficultyLevel": 4,
    "detectionDifficulty": 3,
    "techniques": [
      "T1204.002 - Malicious File",
      "T1027.013 - Encrypted or Encoded File",
      "T1566.001 - Spearphishing Attachment"
    ],
    "mitigation": "Hide or block LNK execution from document extraction paths and inspect Office containers for embedded shortcuts. Apply attachment detonation to catch disguised LNK behavior.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/Embedding%20Object%20in%20office%20document/Scenario2",
    "status": "Detected",
    "tags": [
      "embedded-object",
      "lnk",
      "docx",
      "word",
      "shortcut"
    ]
  },
  {
    "id": "powershell-mouseover-pps",
    "name": "PowerShell Mouseover PPS Payload",
    "category": "Document Execution",
    "description": "A slideshow that uses mouseover interaction in PowerPoint Show format to trigger PowerShell execution.",
    "fullDescription": "Because PPS files open directly in presentation mode, the victim is immediately placed into an interactive slide deck rather than the editor view. The sample demonstrates how action settings tied to hover or click events can launch a PowerShell command with minimal user friction during a presentation workflow.",
    "targetApplications": [
      "PowerPoint",
      "Windows"
    ],
    "attackVector": "PowerPoint Show attachment that relies on interactive slide actions such as mouseover events.",
    "difficultyLevel": 4,
    "detectionDifficulty": 4,
    "techniques": [
      "T1204.002 - Malicious File",
      "T1059.001 - PowerShell",
      "T1566.001 - Spearphishing Attachment"
    ],
    "mitigation": "Disable or heavily restrict PowerPoint action settings from untrusted files and monitor PowerPoint spawning PowerShell. Prefer opening external presentations in Protected View or isolated viewers.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/Execute%20powershell%20on%20mouseover%20-%20Powerpoint%20%28pps%29",
    "status": "Detected",
    "tags": [
      "powerpoint",
      "pps",
      "mouseover",
      "powershell",
      "presentation"
    ]
  },
  {
    "id": "fake-attachment-scam",
    "name": "Fake Attachment Scam",
    "category": "Social Deception",
    "description": "An Outlook lure that pretends to contain sensitive content while steering the victim toward a deceptive workflow.",
    "fullDescription": "This payload focuses on the social engineering stage rather than exploit code by making the message itself the manipulative artifact. The scam uses urgency and confidentiality cues to convince the victim to open a fake attachment path, reply, or trust follow-on instructions from the attacker.",
    "targetApplications": [
      "Outlook"
    ],
    "attackVector": "Deceptive email message masquerading as a confidential attachment notice.",
    "difficultyLevel": 1,
    "detectionDifficulty": 2,
    "techniques": [
      "T1566.002 - Spearphishing Link",
      "T1036 - Masquerading",
      "T1598.003 - Spearphishing Service"
    ],
    "mitigation": "Use mail banner warnings and phishing-awareness training to reduce trust in urgency-driven financial lures. Quarantine messages with suspicious attachment language but no corresponding safe content.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/Fake%20attachment%20scam",
    "status": "Active",
    "tags": [
      "outlook",
      "msg",
      "scam",
      "deception",
      "finance"
    ]
  },
  {
    "id": "link-manipulation",
    "name": "Link Manipulation Attack",
    "category": "Web Attack",
    "description": "A web lure that visually impersonates a Microsoft patch download while silently changing the destination URL.",
    "fullDescription": "The HTML page displays a trustworthy title and visible link text pointing to a legitimate Microsoft bulletin, but JavaScript rewrites the actual href at click time. This mismatch demonstrates classic link manipulation where the user believes they are visiting a safe vendor page yet is redirected to attacker infrastructure.",
    "targetApplications": [
      "Web Browser",
      "Windows"
    ],
    "attackVector": "Malicious HTML page that swaps a benign-looking download link for an attacker-controlled destination.",
    "difficultyLevel": 2,
    "detectionDifficulty": 4,
    "techniques": [
      "T1204.001 - Malicious Link",
      "T1036 - Masquerading",
      "T1566.002 - Spearphishing Link"
    ],
    "mitigation": "Inspect rendered links and final click destinations with browser isolation or secure web gateways. Teach users to verify domains before downloading patches or executables.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/Link%20manipulation%20attack",
    "status": "Active",
    "tags": [
      "html",
      "link-manipulation",
      "browser",
      "redirect",
      "phishing"
    ]
  },
  {
    "id": "pdf-malicious-url",
    "name": "PDF with Malicious URL",
    "category": "Social Deception",
    "description": "A PDF lure that redirects victims to retrieve a secondary JAR payload disguised as a financial document.",
    "fullDescription": "The PDF acts as the trusted first-stage artifact and contains a malicious URL intended to move the victim into a download flow outside the document reader. Pairing the PDF with a similarly themed JAR shows how attackers blend common document types with executable follow-on content to bypass suspicion.",
    "targetApplications": [
      "PDF Reader",
      "Web Browser",
      "Windows"
    ],
    "attackVector": "Phishing document containing a malicious hyperlink that leads to a secondary executable download.",
    "difficultyLevel": 2,
    "detectionDifficulty": 3,
    "techniques": [
      "T1204.001 - Malicious Link",
      "T1204.002 - Malicious File",
      "T1566.001 - Spearphishing Attachment"
    ],
    "mitigation": "Rewrite or detonate document hyperlinks before delivery and block Java archive downloads from unsolicited messages. Flag PDFs that contain external URLs to newly registered or non-business domains.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/PDF%20with%20malicious%20URL",
    "status": "Detected",
    "tags": [
      "pdf",
      "jar",
      "malicious-url",
      "finance",
      "download"
    ]
  },
  {
    "id": "password-protected-document",
    "name": "Password Protected Document Lure",
    "category": "Social Deception",
    "description": "A password-protected document workflow that uses a companion message to bypass content inspection and increase trust.",
    "fullDescription": "The attacker sends an Outlook message together with a protected Office document so scanners cannot easily examine the file contents inline. The email supplies the password or retrieval context, conditioning the victim to manually unlock the attachment and continue the attack chain outside automated security analysis.",
    "targetApplications": [
      "Word",
      "Outlook"
    ],
    "attackVector": "Protected attachment plus separate message-based password delivery to evade scanning and encourage manual opening.",
    "difficultyLevel": 2,
    "detectionDifficulty": 4,
    "techniques": [
      "T1566.001 - Spearphishing Attachment",
      "T1027 - Obfuscated Files or Information",
      "T1036 - Masquerading"
    ],
    "mitigation": "Block encrypted Office attachments from external senders unless approved and detonate them after secure password handling. Alert on emails that deliver passwords for attached documents.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/Password%20protected%20document",
    "status": "Active",
    "tags": [
      "password-protected",
      "docx",
      "outlook",
      "encrypted",
      "evasion"
    ]
  },
  {
    "id": "word-basic-auth-phish",
    "name": "Word Basic Auth Credential Prompt",
    "category": "Credential Theft",
    "description": "A Word document that forces a basic authentication prompt to harvest credentials under the guise of protected content.",
    "fullDescription": "This lure abuses remote content or linked resource behavior in Word so the victim sees what appears to be a legitimate authentication challenge. Entered credentials are handed to attacker-controlled infrastructure, turning a routine document open into a credential capture event.",
    "targetApplications": [
      "Word",
      "Web Browser",
      "Windows"
    ],
    "attackVector": "Malicious Word document that references remote content and triggers a credential prompt.",
    "difficultyLevel": 3,
    "detectionDifficulty": 4,
    "techniques": [
      "T1556 - Modify Authentication Process",
      "T1187 - Forced Authentication",
      "T1566.001 - Spearphishing Attachment"
    ],
    "mitigation": "Restrict automatic outbound authentication from Office and block remote templates or linked objects from untrusted zones. Warn users that documents should not request network credentials unexpectedly.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/Steal%20credential%20using%20a%20word%20document%20which%20pop%20for%20basic%20authentication",
    "status": "Detected",
    "tags": [
      "word",
      "credential-theft",
      "basic-auth",
      "ntlm",
      "remote-content"
    ]
  },
  {
    "id": "fake-excel-login",
    "name": "Fake Excel Credential Harvester",
    "category": "Credential Theft",
    "description": "A fake Excel Online login page that captures usernames and passwords before showing a decoy download.",
    "fullDescription": "The page visually imitates Microsoft Excel or Office online branding to convince the victim they must authenticate before viewing a spreadsheet. Submitted credentials are written server-side and the victim is redirected to a benign-looking file, masking the theft as a failed or completed document download.",
    "targetApplications": [
      "Web Browser",
      "Excel"
    ],
    "attackVector": "Browser-based phishing page themed as an Excel download or preview portal.",
    "difficultyLevel": 2,
    "detectionDifficulty": 5,
    "techniques": [
      "T1056 - Input Capture",
      "T1566.002 - Spearphishing Link",
      "T1585.001 - Establish Accounts: Social Media Accounts"
    ],
    "mitigation": "Use phishing-resistant MFA and domain-aware browser controls to block credential entry on untrusted pages. Detect lookalike Office login themes and server-side credential collection endpoints.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/Steal%20credentials%20using%20fake%20excel%20doc",
    "status": "Active",
    "tags": [
      "excel",
      "phishing-page",
      "credential-theft",
      "login",
      "web"
    ]
  },
  {
    "id": "tabnabbing-attack",
    "name": "Tabnabbing Attack",
    "category": "Web Attack",
    "description": "A browser-based lure that abuses tab focus changes to replace trusted content with a malicious update download flow.",
    "fullDescription": "The sample demonstrates tabnabbing by opening or leaving a benign-looking page visible, then changing the tab content once the victim switches away and back. By timing the replacement to normal browsing behavior, the attacker increases the chance that the victim trusts the forged prompt and downloads malware.",
    "targetApplications": [
      "Web Browser",
      "Windows"
    ],
    "attackVector": "Malicious web page that swaps content after a tab loses focus and returns as a fake security alert.",
    "difficultyLevel": 3,
    "detectionDifficulty": 4,
    "techniques": [
      "T1204.001 - Malicious Link",
      "T1036 - Masquerading",
      "T1566.002 - Spearphishing Link"
    ],
    "mitigation": "Use browser isolation or script restrictions for unknown sites and educate users to distrust surprise download prompts in background tabs. Monitor for pages that alter titles, favicons, or destinations after blur events.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/Tabnabbing%20attack",
    "status": "Active",
    "tags": [
      "tabnabbing",
      "browser",
      "phishing",
      "fake-update",
      "social-engineering"
    ]
  },
  {
    "id": "lnk-hta-calc",
    "name": "LNK Download and Execute HTA",
    "category": "File Execution",
    "description": "A Windows shortcut that downloads and launches an HTA payload to execute code on the host.",
    "fullDescription": "The LNK file masks command execution behind a familiar document or survey icon while invoking mshta or a similar Windows component in the background. This pattern is common in intrusion chains because shortcuts are small, flexible, and can fetch second-stage content only after the victim double-clicks the file.",
    "targetApplications": [
      "Windows"
    ],
    "attackVector": "Malicious LNK attachment that retrieves and runs a remote HTA payload after user execution.",
    "difficultyLevel": 3,
    "detectionDifficulty": 4,
    "techniques": [
      "T1204.002 - Malicious File",
      "T1218.005 - Mshta",
      "T1027.013 - Encrypted or Encoded File"
    ],
    "mitigation": "Block shortcut attachments from email and downloads, and disable mshta.exe where business use is not required. Detect LNK files that launch scripting engines or external URLs.",
    "repositoryPath": "https://github.com/sec-js/socialengineeringpayloads/tree/master/lnk%20-%20download%20and%20execute%20calc%20HTA",
    "status": "Detected",
    "tags": [
      "lnk",
      "hta",
      "mshta",
      "windows",
      "shortcut"
    ]
  }
];

  const state = {
    payloads: [],
    filtered: [],
    searchTerm: '',
    categories: new Set(),
    targetApplications: new Set(),
    maxDifficulty: 5,
    maxDetection: 5,
    statuses: new Set(),
    bookmarksOnly: false,
    compareMode: false,
    compareSet: new Set(),
    activePreset: 'all',
    statAnimated: false,
    expandedIds: new Set()
  };

  const dom = {};
  let toastTimer;

  document.addEventListener('DOMContentLoaded', init);
  window.addEventListener('hashchange', handleHashRoute);

  async function init() {
    cacheDom();
    bindEvents();
    initTheme();
    renderLoadingSkeleton();
    state.payloads = await loadPayloads();
    renderCategoryTree();
    syncFilterLabels();
    applyFilters(true);
    handleHashRoute();
  }

  function cacheDom() {
    dom.html = document.documentElement;
    dom.body = document.body;
    dom.sidebar = document.getElementById('sidebar');
    dom.mobileMenuBtn = document.getElementById('mobile-menu-btn');
    dom.searchInput = document.getElementById('search-input');
    dom.cardsGrid = document.getElementById('cards-grid');
    dom.emptyState = document.getElementById('empty-state');
    dom.resultsCount = document.getElementById('results-count');
    dom.activeFilters = document.getElementById('active-filters-display');
    dom.clearFiltersBtn = document.getElementById('clear-filters-btn');
    dom.resetSearchBtn = document.getElementById('reset-search-btn');
    dom.compareBtn = document.getElementById('compare-btn');
    dom.exportJsonBtn = document.getElementById('export-json-btn');
    dom.exportCsvBtn = document.getElementById('export-csv-btn');
    dom.themeToggle = document.getElementById('theme-toggle');
    dom.breadcrumb = document.querySelector('#breadcrumb ol');
    dom.categoryTree = document.getElementById('category-tree');
    dom.quickFilterButtons = Array.from(document.querySelectorAll('[data-preset]'));
    dom.categoryChecks = Array.from(document.querySelectorAll('input[name="category-filter"]'));
    dom.targetChecks = Array.from(document.querySelectorAll('input[name="target-filter"]'));
    dom.statusChecks = Array.from(document.querySelectorAll('input[name="status-filter"]'));
    dom.difficultyRange = document.getElementById('difficulty-range');
    dom.detectionRange = document.getElementById('detection-range');
    dom.difficultyValue = document.getElementById('difficulty-value');
    dom.detectionValue = document.getElementById('detection-value');
    dom.comparisonModal = document.getElementById('comparison-modal');
    dom.closeComparison = document.getElementById('close-comparison');
    dom.comparisonContainer = document.getElementById('comparison-table-container');
    dom.toast = document.getElementById('toast');
    dom.stats = {
      total: document.querySelector('#stat-total .stat-number'),
      categories: document.querySelector('#stat-categories .stat-number'),
      avgDifficulty: document.querySelector('#stat-avg-difficulty .stat-number'),
      active: document.querySelector('#stat-active .stat-number')
    };
    dom.statCards = {
      total: document.getElementById('stat-total'),
      categories: document.getElementById('stat-categories'),
      avgDifficulty: document.getElementById('stat-avg-difficulty'),
      active: document.getElementById('stat-active')
    };
  }

  function bindEvents() {
    const onSearch = debounce((event) => {
      state.searchTerm = event.target.value.trim().toLowerCase();
      applyFilters();
    }, 200);

    dom.searchInput.addEventListener('input', onSearch);
    dom.categoryChecks.forEach((checkbox) => checkbox.addEventListener('change', handleCheckboxFilters));
    dom.targetChecks.forEach((checkbox) => checkbox.addEventListener('change', handleCheckboxFilters));
    dom.statusChecks.forEach((checkbox) => checkbox.addEventListener('change', handleCheckboxFilters));

    dom.difficultyRange.addEventListener('input', (event) => {
      state.maxDifficulty = Number(event.target.value);
      dom.difficultyValue.textContent = `1-${state.maxDifficulty}`;
      applyFilters();
    });

    dom.detectionRange.addEventListener('input', (event) => {
      state.maxDetection = Number(event.target.value);
      dom.detectionValue.textContent = `1-${state.maxDetection}`;
      applyFilters();
    });

    dom.quickFilterButtons.forEach((button) => {
      button.addEventListener('click', () => applyPreset(button.dataset.preset));
    });

    dom.clearFiltersBtn.addEventListener('click', resetFilters);
    dom.resetSearchBtn.addEventListener('click', resetFilters);
    dom.exportJsonBtn.addEventListener('click', exportJSON);
    dom.exportCsvBtn.addEventListener('click', exportCSV);
    dom.themeToggle.addEventListener('click', toggleTheme);
    dom.mobileMenuBtn.addEventListener('click', toggleMobileNav);
    dom.compareBtn.addEventListener('click', showComparisonModal);
    dom.closeComparison.addEventListener('click', closeComparisonModal);

    dom.comparisonModal.addEventListener('click', (event) => {
      if (event.target === dom.comparisonModal) {
        closeComparisonModal();
      }
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        closeComparisonModal();
        closeMobileNav();
      }
    });

    dom.cardsGrid.addEventListener('click', handleCardActions);
    dom.categoryTree.addEventListener('click', handleTreeActions);
  }

  async function loadPayloads() {
    if (window.location.protocol === 'file:') {
      return structuredClone(FALLBACK_PAYLOADS);
    }

    const candidates = ['assets/data/payloads.json', './assets/data/payloads.json'];
    for (const url of candidates) {
      try {
        const response = await fetch(url, { cache: 'no-store' });
        if (!response.ok) {
          continue;
        }
        const data = await response.json();
        return Array.isArray(data) ? data : structuredClone(FALLBACK_PAYLOADS);
      } catch (error) {
        // keep trying
      }
    }
    return structuredClone(FALLBACK_PAYLOADS);
  }

  function handleCheckboxFilters() {
    state.categories = new Set(dom.categoryChecks.filter((input) => input.checked).map((input) => input.value));
    state.targetApplications = new Set(dom.targetChecks.filter((input) => input.checked).map((input) => input.value));
    state.statuses = new Set(dom.statusChecks.filter((input) => input.checked).map((input) => input.value));
    applyFilters();
  }

  function applyPreset(preset) {
    state.activePreset = preset;
    state.bookmarksOnly = preset === 'bookmarked';
    dom.quickFilterButtons.forEach((button) => {
      button.classList.toggle('active', button.dataset.preset === preset);
    });
    applyFilters();
  }

  function applyFilters(initial = false) {
    let filtered = state.payloads.filter((payload) => matchesSearch(payload, state.searchTerm));

    filtered = filtered.filter((payload) => {
      const categoryMatch = !state.categories.size || state.categories.has(payload.category);
      const targetMatch = !state.targetApplications.size || payload.targetApplications.some((app) => state.targetApplications.has(app));
      const difficultyMatch = payload.difficultyLevel <= state.maxDifficulty;
      const detectionMatch = payload.detectionDifficulty <= state.maxDetection;
      const statusMatch = !state.statuses.size || state.statuses.has(payload.status);
      const bookmarkMatch = !state.bookmarksOnly || isBookmarked(payload.id);
      const presetMatch = matchesPreset(payload, state.activePreset);
      return categoryMatch && targetMatch && difficultyMatch && detectionMatch && statusMatch && bookmarkMatch && presetMatch;
    });

    state.filtered = filtered;
    renderCards(filtered);
    updateStats(filtered, initial);
    updateResultsBar(filtered);
    updateBreadcrumb();
    updateCompareButton();
    syncFilterLabels();
  }

  function matchesSearch(payload, term) {
    if (!term) {
      return true;
    }

    const haystack = [
      payload.name,
      payload.description,
      payload.fullDescription,
      payload.attackVector,
      ...(payload.tags || []),
      ...(payload.techniques || []),
      ...(payload.targetApplications || [])
    ].join(' ').toLowerCase();

    return haystack.includes(term);
  }

  function matchesPreset(payload, preset) {
    switch (preset) {
      case 'hardest':
        return payload.detectionDifficulty >= 4;
      case 'beginner':
        return payload.difficultyLevel <= 2;
      case 'credential':
        return payload.category === 'Credential Theft';
      case 'web':
        return payload.category === 'Web Attack';
      case 'bookmarked':
      case 'all':
      default:
        return true;
    }
  }

  function renderCards(payloads) {
    dom.cardsGrid.innerHTML = '';
    if (!payloads.length) {
      dom.emptyState.hidden = false;
      return;
    }
    dom.emptyState.hidden = true;
    payloads.forEach((payload) => {
      dom.cardsGrid.appendChild(renderCard(payload));
    });
  }

  function renderCard(payload) {
    const article = document.createElement('article');
    article.className = 'payload-card';
    article.id = `payload-${payload.id}`;
    article.dataset.payloadId = payload.id;
    article.setAttribute('role', 'listitem');
    article.classList.toggle('is-compared', state.compareSet.has(payload.id));

    const relatedLinks = getRelated(payload).map((item) => `<a href="#${item.id}" data-related-id="${escapeHtml(item.id)}">${escapeHtml(item.name)}</a>`).join('');
    const techniqueLinks = payload.techniques.map((technique) => techniqueToLink(technique)).join('');
    const targetBadges = payload.targetApplications.map((app) => `<span class="app-badge">${escapeHtml(app)}</span>`).join('');
    const tagBadges = payload.tags.map((tag) => `<span class="tag-badge">#${escapeHtml(tag)}</span>`).join('');
    const detectionPercent = Math.round((payload.detectionDifficulty / 5) * 100);
    const expanded = state.expandedIds.has(payload.id);
    const hashLink = `#${payload.id}`;

    article.innerHTML = `
      <div class="card-header">
        <div class="card-title-wrap">
          <div class="card-topline">
            <span class="category-badge">${escapeHtml(payload.category)}</span>
            <span class="status-badge" data-status="${escapeHtml(payload.status)}">${escapeHtml(payload.status)}</span>
          </div>
          <h2 class="card-title">${escapeHtml(payload.name)}</h2>
          <p class="card-description">${escapeHtml(payload.description)}</p>
        </div>
        <div class="card-actions" aria-label="Card actions">
          <button class="icon-btn bookmark-btn ${isBookmarked(payload.id) ? 'active' : ''}" data-action="bookmark" data-id="${escapeHtml(payload.id)}" aria-label="Toggle bookmark">♥</button>
          <button class="icon-btn compare-action ${state.compareSet.has(payload.id) ? 'active' : ''}" data-action="compare" data-id="${escapeHtml(payload.id)}" aria-label="Add to comparison">⇄</button>
          <button class="icon-btn share-action" data-action="share" data-id="${escapeHtml(payload.id)}" aria-label="Share payload">⤴</button>
        </div>
      </div>

      <div class="badge-row" aria-label="Target applications">${targetBadges}</div>

      <div class="card-meta">
        <span><strong>Attack vector:</strong> ${escapeHtml(payload.attackVector)}</span>
      </div>

      <div class="card-meta">
        <span><strong>Difficulty:</strong> <span class="difficulty-stars" aria-label="Difficulty ${payload.difficultyLevel} out of 5">${renderStars(payload.difficultyLevel)}</span></span>
        <div class="detection-wrap">
          <span><strong>Detection difficulty:</strong> ${payload.detectionDifficulty}/5</span>
          <div class="detection-bar" aria-label="Detection difficulty ${payload.detectionDifficulty} out of 5">
            <div class="detection-fill" style="width:${detectionPercent}%"></div>
          </div>
        </div>
      </div>

      <div class="badge-row" aria-label="Techniques and tags">
        ${payload.techniques.map((technique) => `<span class="technique-badge">${escapeHtml(technique)}</span>`).join('')}
        ${tagBadges}
      </div>

      <div class="card-footer">
        <button class="learn-more-btn" data-action="toggle-details" data-id="${escapeHtml(payload.id)}" aria-expanded="${expanded}" aria-controls="details-${escapeHtml(payload.id)}">
          ${expanded ? 'Hide Details' : 'Learn More'}
        </button>
        <a class="card-link" href="${escapeHtml(payload.repositoryPath)}" target="_blank" rel="noopener noreferrer">View in Repo ↗</a>
      </div>

      <section class="expanded-section" id="details-${escapeHtml(payload.id)}" ${expanded ? '' : 'hidden'}>
        <div>
          <h3 class="section-title">Technical Detail</h3>
          <p>${escapeHtml(payload.fullDescription)}</p>
        </div>
        <div>
          <h3 class="section-title">Mitigation</h3>
          <p>${escapeHtml(payload.mitigation)}</p>
        </div>
        <div>
          <h3 class="section-title">MITRE ATT&CK</h3>
          <div class="technique-links">${techniqueLinks}</div>
        </div>
        <div>
          <h3 class="section-title">Related Payloads</h3>
          <div class="related-list">${relatedLinks || '<span class="tag-badge">No related payloads</span>'}</div>
        </div>
        <div>
          <h3 class="section-title">Catalog Tags</h3>
          <div class="badge-row">${tagBadges}</div>
        </div>
      </section>
    `;

    return article;
  }

  function updateStats(payloads, initial = false) {
    const total = payloads.length;
    const categoryCount = new Set(payloads.map((payload) => payload.category)).size;
    const avgDifficulty = total ? (payloads.reduce((sum, payload) => sum + payload.difficultyLevel, 0) / total).toFixed(1) : '0.0';
    const activeCount = payloads.filter((payload) => payload.status === 'Active').length;
    const topApp = getMostCommonTargetApp(payloads);

    setStat(dom.stats.total, total, initial && !state.statAnimated);
    setStat(dom.stats.categories, categoryCount, initial && !state.statAnimated);
    setStat(dom.stats.avgDifficulty, Number(avgDifficulty), initial && !state.statAnimated, 1);
    setStat(dom.stats.active, activeCount, initial && !state.statAnimated);

    setStatDetail(dom.statCards.total, `${total === state.payloads.length ? 'Full catalog view' : 'Filtered subset'} · ${state.payloads.length} indexed`);
    setStatDetail(dom.statCards.categories, `Top app: ${topApp || 'N/A'}`);
    setStatDetail(dom.statCards.avgDifficulty, `Search + filters update this metric`);
    setStatDetail(dom.statCards.active, `${activeCount} active / ${payloads.length || 0} shown`);

    if (initial) {
      state.statAnimated = true;
    }
  }

  function setStat(element, value, animate = false, decimals = 0) {
    if (!animate) {
      element.textContent = decimals ? Number(value).toFixed(decimals) : String(value);
      return;
    }

    const start = performance.now();
    const duration = 800;
    const target = Number(value);

    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const current = target * easeOutCubic(progress);
      element.textContent = decimals ? current.toFixed(decimals) : String(Math.round(current));
      if (progress < 1) {
        requestAnimationFrame(tick);
      } else {
        element.textContent = decimals ? target.toFixed(decimals) : String(target);
      }
    }

    requestAnimationFrame(tick);
  }

  function setStatDetail(card, text) {
    let detail = card.querySelector('.stat-detail');
    if (!detail) {
      detail = document.createElement('span');
      detail.className = 'stat-detail';
      card.appendChild(detail);
    }
    detail.textContent = text;
  }

  function updateResultsBar(payloads) {
    dom.resultsCount.textContent = `Showing ${payloads.length} of ${state.payloads.length} payloads`;
    dom.activeFilters.innerHTML = '';
    const chips = buildActiveFilterChips();
    chips.forEach((label) => {
      const chip = document.createElement('span');
      chip.className = 'filter-chip';
      chip.textContent = label;
      dom.activeFilters.appendChild(chip);
    });
    if (!chips.length) {
      const chip = document.createElement('span');
      chip.className = 'filter-chip';
      chip.textContent = 'No active filters';
      dom.activeFilters.appendChild(chip);
    }
  }

  function buildActiveFilterChips() {
    const chips = [];
    if (state.searchTerm) chips.push(`Search: ${state.searchTerm}`);
    if (state.categories.size) chips.push(`Category: ${Array.from(state.categories).join(', ')}`);
    if (state.targetApplications.size) chips.push(`Target: ${Array.from(state.targetApplications).join(', ')}`);
    if (state.statuses.size) chips.push(`Status: ${Array.from(state.statuses).join(', ')}`);
    if (state.maxDifficulty < 5) chips.push(`Difficulty ≤ ${state.maxDifficulty}`);
    if (state.maxDetection < 5) chips.push(`Detection ≤ ${state.maxDetection}`);
    if (state.bookmarksOnly) chips.push('Bookmarked only');
    if (state.activePreset && state.activePreset !== 'all' && state.activePreset !== 'bookmarked') {
      const labelMap = {
        hardest: 'Hardest to Detect',
        beginner: 'Beginner Friendly',
        credential: 'Credential Theft',
        web: 'Web Attacks'
      };
      chips.push(`Preset: ${labelMap[state.activePreset]}`);
    }
    return chips;
  }

  function updateBreadcrumb() {
    const items = ['Home'];
    if (state.activePreset !== 'all') {
      const presetNames = {
        hardest: 'Hardest to Detect',
        beginner: 'Beginner Friendly',
        credential: 'Credential Theft',
        web: 'Web Attacks',
        bookmarked: 'Bookmarked'
      };
      items.push(presetNames[state.activePreset]);
    }
    if (state.categories.size) {
      items.push(...state.categories);
    }
    if (state.targetApplications.size) {
      items.push(...state.targetApplications);
    }
    if (state.searchTerm) {
      items.push(`Search: ${state.searchTerm}`);
    }

    dom.breadcrumb.innerHTML = '';
    items.forEach((item, index) => {
      const li = document.createElement('li');
      if (index === items.length - 1) {
        const span = document.createElement('span');
        span.setAttribute('aria-current', 'page');
        span.textContent = item;
        li.appendChild(span);
      } else {
        const link = document.createElement('a');
        link.href = '#';
        link.textContent = item;
        if (index === 0) {
          link.addEventListener('click', (event) => {
            event.preventDefault();
            resetFilters();
          });
        }
        li.appendChild(link);
      }
      dom.breadcrumb.appendChild(li);
    });
  }

  function renderCategoryTree() {
    const groups = state.payloads.reduce((map, payload) => {
      if (!map.has(payload.category)) {
        map.set(payload.category, []);
      }
      map.get(payload.category).push(payload);
      return map;
    }, new Map());

    const fragment = document.createDocumentFragment();
    Array.from(groups.entries()).sort((a, b) => a[0].localeCompare(b[0])).forEach(([category, items]) => {
      const details = document.createElement('details');
      details.open = state.categories.has(category);
      const summary = document.createElement('summary');
      summary.textContent = `${category} (${items.length})`;
      details.appendChild(summary);
      const list = document.createElement('ul');
      items.forEach((payload) => {
        const li = document.createElement('li');
        li.className = 'tree-leaf';
        li.innerHTML = `<button type="button" data-tree-payload="${escapeHtml(payload.id)}">${escapeHtml(payload.name)}</button>`;
        list.appendChild(li);
      });
      details.appendChild(list);
      fragment.appendChild(details);
    });

    dom.categoryTree.innerHTML = '';
    dom.categoryTree.appendChild(fragment);
  }

  function handleTreeActions(event) {
    const payloadId = event.target.dataset.treePayload;
    if (!payloadId) {
      return;
    }
    event.preventDefault();
    const payload = state.payloads.find((item) => item.id === payloadId);
    if (!payload) {
      return;
    }
    state.categories = new Set([payload.category]);
    dom.categoryChecks.forEach((input) => {
      input.checked = state.categories.has(input.value);
    });
    applyFilters();
    openPayload(payloadId);
  }

  function handleCardActions(event) {
    const actionTarget = event.target.closest('[data-action], [data-related-id]');
    if (!actionTarget) {
      return;
    }

    if (actionTarget.dataset.relatedId) {
      event.preventDefault();
      openPayload(actionTarget.dataset.relatedId);
      return;
    }

    const { action, id } = actionTarget.dataset;
    switch (action) {
      case 'bookmark':
        toggleBookmark(id);
        break;
      case 'compare':
        toggleCompare(id);
        break;
      case 'share':
        sharePayload(id);
        break;
      case 'toggle-details':
        toggleDetails(id);
        break;
      default:
        break;
    }
  }

  function toggleDetails(id, forceOpen = null) {
    const shouldOpen = forceOpen === null ? !state.expandedIds.has(id) : forceOpen;
    if (shouldOpen) {
      state.expandedIds.add(id);
      history.replaceState(null, '', `#${id}`);
    } else {
      state.expandedIds.delete(id);
      if (window.location.hash === `#${id}`) {
        history.replaceState(null, '', window.location.pathname + window.location.search);
      }
    }
    renderCards(state.filtered);
    if (shouldOpen) {
      highlightCard(id);
    }
  }

  function openPayload(id) {
    if (!state.filtered.some((payload) => payload.id === id)) {
      const payload = state.payloads.find((item) => item.id === id);
      if (payload) {
        state.categories.clear();
        state.targetApplications.clear();
        state.statuses.clear();
        dom.categoryChecks.forEach((input) => { input.checked = false; });
        dom.targetChecks.forEach((input) => { input.checked = false; });
        dom.statusChecks.forEach((input) => { input.checked = false; });
        applyFilters();
      }
    }
    toggleDetails(id, true);
  }

  function highlightCard(id) {
    requestAnimationFrame(() => {
      const card = document.getElementById(`payload-${id}`);
      if (!card) {
        return;
      }
      card.classList.add('is-highlighted');
      card.scrollIntoView({ behavior: 'smooth', block: 'center' });
      setTimeout(() => card.classList.remove('is-highlighted'), 1200);
    });
  }

  function getRelated(payload) {
    return state.payloads.filter((candidate) => candidate.category === payload.category && candidate.id !== payload.id).slice(0, 3);
  }

  function toggleBookmark(id) {
    const bookmarks = getBookmarks();
    if (bookmarks.includes(id)) {
      saveBookmarks(bookmarks.filter((entry) => entry !== id));
      showToast('Removed bookmark');
    } else {
      bookmarks.push(id);
      saveBookmarks(bookmarks);
      showToast('Bookmarked payload');
    }
    renderCards(state.filtered);
    updateResultsBar(state.filtered);
  }

  function isBookmarked(id) {
    return getBookmarks().includes(id);
  }

  function filterBookmarked() {
    applyPreset('bookmarked');
  }

  function toggleCompare(id) {
    if (state.compareSet.has(id)) {
      state.compareSet.delete(id);
      showToast('Removed from comparison');
    } else {
      if (state.compareSet.size >= 3) {
        showToast('Select up to 3 payloads for comparison');
        return;
      }
      state.compareSet.add(id);
      showToast('Added to comparison');
    }
    updateCompareButton();
    renderCards(state.filtered);
  }

  function updateCompareButton() {
    const count = state.compareSet.size;
    dom.compareBtn.style.display = count ? 'inline-flex' : 'none';
    dom.compareBtn.textContent = count > 1 ? `Compare Selected (${count})` : `Select ${2 - count} more to compare`;
    dom.compareBtn.disabled = count < 2;
  }

  function showComparisonModal() {
    if (state.compareSet.size < 2) {
      showToast('Select at least 2 payloads');
      return;
    }
    const selected = state.payloads.filter((payload) => state.compareSet.has(payload.id));
    const rows = [
      ['Category', selected.map((payload) => payload.category)],
      ['Target Applications', selected.map((payload) => payload.targetApplications.join(', '))],
      ['Difficulty', selected.map((payload) => `${payload.difficultyLevel}/5`)],
      ['Detection Difficulty', selected.map((payload) => `${payload.detectionDifficulty}/5`)],
      ['Attack Vector', selected.map((payload) => payload.attackVector)],
      ['Techniques', selected.map((payload) => payload.techniques.join(', '))],
      ['Status', selected.map((payload) => payload.status)],
      ['Mitigation', selected.map((payload) => payload.mitigation)]
    ];

    let html = '<table class="comparison-table"><thead><tr><th>Field</th>';
    html += selected.map((payload) => `<th>${escapeHtml(payload.name)}</th>`).join('');
    html += '</tr></thead><tbody>';
    rows.forEach(([label, values]) => {
      html += `<tr><th>${escapeHtml(label)}</th>${values.map((value) => `<td>${escapeHtml(value)}</td>`).join('')}</tr>`;
    });
    html += '</tbody></table>';
    dom.comparisonContainer.innerHTML = html;
    dom.comparisonModal.hidden = false;
    dom.compareMode = true;
  }

  function closeComparisonModal() {
    if (dom.comparisonModal.hidden) {
      return;
    }
    dom.comparisonModal.hidden = true;
    dom.compareMode = false;
  }

  function exportJSON() {
    downloadFile('sep-dashboard-export.json', JSON.stringify(state.filtered, null, 2), 'application/json');
    showToast('Exported filtered results as JSON');
  }

  function exportCSV() {
    const headers = ['id', 'name', 'category', 'description', 'attackVector', 'difficultyLevel', 'detectionDifficulty', 'status', 'targetApplications', 'techniques', 'tags', 'repositoryPath'];
    const lines = [headers.join(',')];
    state.filtered.forEach((payload) => {
      const row = [
        payload.id,
        payload.name,
        payload.category,
        payload.description,
        payload.attackVector,
        payload.difficultyLevel,
        payload.detectionDifficulty,
        payload.status,
        payload.targetApplications.join('; '),
        payload.techniques.join('; '),
        payload.tags.join('; '),
        payload.repositoryPath
      ].map(csvEscape);
      lines.push(row.join(','));
    });
    downloadFile('sep-dashboard-export.csv', lines.join('\n'), 'text/csv;charset=utf-8');
    showToast('Exported filtered results as CSV');
  }

  function downloadFile(filename, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function initTheme() {
    const savedTheme = localStorage.getItem(STORAGE_KEYS.theme) || 'dark';
    dom.html.setAttribute('data-theme', savedTheme);
    updateThemeToggleLabel(savedTheme);
  }

  function toggleTheme() {
    const current = dom.html.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    dom.html.setAttribute('data-theme', next);
    localStorage.setItem(STORAGE_KEYS.theme, next);
    updateThemeToggleLabel(next);
    showToast(`${capitalize(next)} theme enabled`);
  }

  function updateThemeToggleLabel(theme) {
    dom.themeToggle.textContent = theme === 'dark' ? '☀' : '☾';
    dom.themeToggle.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`);
  }

  async function sharePayload(id) {
    const payload = state.payloads.find((item) => item.id === id);
    if (!payload) {
      return;
    }
    const url = `${window.location.origin}${window.location.pathname}#${payload.id}`;
    if (navigator.share) {
      try {
        await navigator.share({ title: payload.name, text: payload.description, url });
        showToast('Share sheet opened');
        return;
      } catch (error) {
        // continue to clipboard fallback
      }
    }
    try {
      await navigator.clipboard.writeText(url);
      showToast('Payload link copied to clipboard');
    } catch (error) {
      showToast('Copy this link manually from the address bar');
    }
  }

  function handleHashRoute() {
    const id = window.location.hash.replace('#', '');
    if (!id) {
      return;
    }
    const payload = state.payloads.find((item) => item.id === id);
    if (!payload) {
      return;
    }
    openPayload(id);
  }

  function toggleMobileNav() {
    const open = dom.sidebar.classList.toggle('open');
    dom.body.classList.toggle('sidebar-open', open);
    dom.mobileMenuBtn.setAttribute('aria-expanded', String(open));
  }

  function closeMobileNav() {
    dom.sidebar.classList.remove('open');
    dom.body.classList.remove('sidebar-open');
    dom.mobileMenuBtn.setAttribute('aria-expanded', 'false');
  }

  function resetFilters() {
    state.searchTerm = '';
    state.categories.clear();
    state.targetApplications.clear();
    state.statuses.clear();
    state.bookmarksOnly = false;
    state.activePreset = 'all';
    state.maxDifficulty = 5;
    state.maxDetection = 5;

    dom.searchInput.value = '';
    dom.difficultyRange.value = '5';
    dom.detectionRange.value = '5';
    dom.categoryChecks.forEach((input) => { input.checked = false; });
    dom.targetChecks.forEach((input) => { input.checked = false; });
    dom.statusChecks.forEach((input) => { input.checked = false; });
    dom.quickFilterButtons.forEach((button) => button.classList.toggle('active', button.dataset.preset === 'all'));
    syncFilterLabels();
    applyFilters();
    history.replaceState(null, '', window.location.pathname + window.location.search);
    closeMobileNav();
  }

  function syncFilterLabels() {
    dom.difficultyValue.textContent = `1-${state.maxDifficulty}`;
    dom.detectionValue.textContent = `1-${state.maxDetection}`;
  }

  function renderLoadingSkeleton() {
    dom.cardsGrid.innerHTML = Array.from({ length: 6 }, () => `
      <div class="skeleton-card" aria-hidden="true">
        <div class="loading-line short"></div>
        <div class="loading-line mid"></div>
        <div class="loading-line long"></div>
        <div class="loading-line long"></div>
        <div class="loading-line mid"></div>
      </div>
    `).join('');
  }

  function renderStars(level) {
    return '★'.repeat(level) + '☆'.repeat(5 - level);
  }

  function techniqueToLink(technique) {
    const match = technique.match(/(T\d{4}(?:\.\d{3})?)/);
    const id = match ? match[1] : null;
    const path = id ? id.replace('.', '/') : '';
    const href = path ? `https://attack.mitre.org/techniques/${path}/` : 'https://attack.mitre.org/';
    return `<a class="technique-badge" href="${href}" target="_blank" rel="noopener noreferrer">${escapeHtml(technique)}</a>`;
  }

  function getMostCommonTargetApp(payloads) {
    const counts = new Map();
    payloads.forEach((payload) => {
      payload.targetApplications.forEach((app) => {
        counts.set(app, (counts.get(app) || 0) + 1);
      });
    });
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || '';
  }

  function getBookmarks() {
    try {
      const parsed = JSON.parse(localStorage.getItem(STORAGE_KEYS.bookmarks) || '[]');
      return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
      return [];
    }
  }

  function saveBookmarks(bookmarks) {
    localStorage.setItem(STORAGE_KEYS.bookmarks, JSON.stringify(bookmarks));
  }

  function csvEscape(value) {
    const text = String(value ?? '');
    return `"${text.replace(/"/g, '""')}"`;
  }

  function showToast(message) {
    clearTimeout(toastTimer);
    dom.toast.textContent = message;
    dom.toast.classList.add('show');
    toastTimer = setTimeout(() => dom.toast.classList.remove('show'), 2200);
  }

  function debounce(fn, wait) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), wait);
    };
  }

  function easeOutCubic(value) {
    return 1 - Math.pow(1 - value, 3);
  }

  function capitalize(value) {
    return value.charAt(0).toUpperCase() + value.slice(1);
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  window.SEPDashboard = {
    exportJSON,
    exportCSV,
    filterBookmarked,
    toggleTheme,
    toggleBookmark,
    toggleCompare,
    showComparisonModal
  };
})();
