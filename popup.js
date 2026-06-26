/**
 * ParamXray - popup.js
 * UI controller, data merges, and dynamic popup rendering logic.
 */

document.addEventListener("DOMContentLoaded", () => {
  // UI Elements
  const btnAnalyze = document.getElementById("btn-analyze");
  const btnExport = document.getElementById("btn-export");
  const targetDomainSpan = document.getElementById("target-domain");
  const scanStatusSpan = document.getElementById("scan-status");
  const badgeLeaks = document.getElementById("badge-leaks");

  // Counters
  const countParams = document.getElementById("count-params");
  const countForms = document.getElementById("count-forms");
  const countSubdomains = document.getElementById("count-subdomains");
  const countResources = document.getElementById("count-resources");
  const countLeaks = document.getElementById("count-leaks");

  // Output Containers
  const listParams = document.getElementById("list-params");
  const listForms = document.getElementById("list-forms");
  const listSubdomains = document.getElementById("list-subdomains");
  const listResources = document.getElementById("list-resources");
  const listLeaks = document.getElementById("list-leaks");

  // Tab Navigation Links
  const tabs = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  // Global State for exported report
  let sessionData = {
    parameters: [],
    formFields: [],
    subdomains: [],
    resources: [],
    leaks: [],
    metadata: {
      url: "",
      title: "",
      timestamp: ""
    }
  };

  // 1. Tab Switching Controller
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tabPanes.forEach(pane => pane.classList.remove("active"));

      tab.classList.add("active");
      const targetPane = document.getElementById(`tab-${tab.dataset.tab}`);
      if (targetPane) {
        targetPane.classList.add("active");
      }
    });
  });

  // Fetch initial active tab details and pre-load background resources
  chrome.tabs.query({ active: true, currentWindow: true }, (activeTabs) => {
    if (chrome.runtime.lastError || !activeTabs || activeTabs.length === 0) {
      console.warn("Could not retrieve active tab context:", chrome.runtime.lastError);
      return;
    }

    const currentTab = activeTabs[0];
    try {
      const url = new URL(currentTab.url);
      targetDomainSpan.textContent = url.hostname;
      
      // Load passively collected network requests immediately
      loadNetworkRequests(currentTab.id);
    } catch (e) {
      targetDomainSpan.textContent = "Unknown Tab";
    }
  });

  // 2. Click Handler - Analyze Page DOM
  btnAnalyze.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (activeTabs) => {
      if (chrome.runtime.lastError || !activeTabs || activeTabs.length === 0) {
        alert("Unable to access current tab context.");
        return;
      }

      const activeTab = activeTabs[0];
      
      // Update UI Status
      scanStatusSpan.textContent = "SCANNING";
      scanStatusSpan.className = "stat-value text-amber";
      btnAnalyze.disabled = true;

      // Inject content.js directly into tab context
      chrome.scripting.executeScript({
        target: { tabId: activeTab.id },
        files: ["content.js"]
      }, (results) => {
        btnAnalyze.disabled = false;
        
        if (chrome.runtime.lastError || !results || !results[0]) {
          console.error("Script execution failed:", chrome.runtime.lastError);
          scanStatusSpan.textContent = "FAILED";
          scanStatusSpan.className = "stat-value text-amber";
          alert("Injection failed. ParamXray cannot scan restricted browser pages (e.g. chrome:// links or Web Store).");
          return;
        }

        const data = results[0].result;
        
        if (data.error) {
          console.error("DOM Extractor returned error:", data.error);
          scanStatusSpan.textContent = "FAILED";
          scanStatusSpan.className = "stat-value text-amber";
          return;
        }

        // Complete DOM extraction processing
        processReconData(activeTab.id, data);
      });
    });
  });

  // 3. Merging and populating variables
  function loadNetworkRequests(tabId) {
    const key = `network_requests_${tabId}`;
    chrome.storage.session.get([key], (result) => {
      const networkApis = result[key] || [];
      
      // Pre-populate overview count and resources tab
      sessionData.resources = Array.from(new Set([...sessionData.resources, ...networkApis]));
      updateOverviewCounts();
      renderResources();
    });
  }

  function processReconData(tabId, domData) {
    // Save metadata
    sessionData.metadata = {
      url: domData.scanMetadata.url,
      title: domData.scanMetadata.title,
      timestamp: domData.scanMetadata.timestamp
    };

    // Update Domain Display
    try {
      const parsedUrl = new URL(domData.scanMetadata.url);
      targetDomainSpan.textContent = parsedUrl.hostname;
    } catch(e) {
      targetDomainSpan.textContent = "Extracted Tab";
    }

    // Merge Parameters
    sessionData.parameters = domData.parameters || [];
    
    // Merge Form Fields
    sessionData.formFields = domData.formFields || [];

    // Merge Subdomains
    sessionData.subdomains = domData.subdomains || [];

    // Retrieve passively logged network items, then merge script resources
    const key = `network_requests_${tabId}`;
    chrome.storage.session.get([key], (result) => {
      const networkApis = result[key] || [];
      const domScripts = domData.domScripts || [];
      
      // Combined resources
      sessionData.resources = Array.from(new Set([...domScripts, ...networkApis]));
      
      // Secrets
      sessionData.leaks = domData.leaks || [];

      // Render
      renderAllTabs();
      
      // Update Status and counters
      scanStatusSpan.textContent = "FINISHED";
      scanStatusSpan.className = "stat-value text-green";
    });
  }

  // 4. Multi-tab renderer
  function renderAllTabs() {
    updateOverviewCounts();
    renderParams();
    renderSubdomains();
    renderResources();
    renderLeaks();
  }

  function updateOverviewCounts() {
    countParams.textContent = sessionData.parameters.length;
    countForms.textContent = sessionData.formFields.length;
    countSubdomains.textContent = sessionData.subdomains.length;
    countResources.textContent = sessionData.resources.length;
    countLeaks.textContent = sessionData.leaks.length;

    // Badges update
    if (sessionData.leaks.length > 0) {
      badgeLeaks.textContent = sessionData.leaks.length;
      badgeLeaks.classList.remove("hidden");
    } else {
      badgeLeaks.classList.add("hidden");
    }
  }

  function renderParams() {
    listParams.innerHTML = "";
    listForms.innerHTML = "";

    // 1. Render URL Query parameters
    if (sessionData.parameters.length === 0) {
      listParams.innerHTML = `<tr><td colspan="3" class="text-secondary" style="text-align: center;">No URL parameters detected.</td></tr>`;
    } else {
      sessionData.parameters.forEach(item => {
        const row = document.createElement("tr");
        
        const cellParam = document.createElement("td");
        cellParam.textContent = item.parameter;
        cellParam.title = item.parameter;
        
        const cellVal = document.createElement("td");
        cellVal.textContent = item.sampleValue || "[empty]";
        cellVal.title = item.sampleValue;
        
        const cellSource = document.createElement("td");
        cellSource.textContent = item.sourceUrl;
        cellSource.title = item.sourceUrl;

        row.appendChild(cellParam);
        row.appendChild(cellVal);
        row.appendChild(cellSource);
        listParams.appendChild(row);
      });
    }

    // 2. Render Form input components
    if (sessionData.formFields.length === 0) {
      listForms.innerHTML = `<tr><td colspan="3" class="text-secondary" style="text-align: center;">No form input elements detected.</td></tr>`;
    } else {
      sessionData.formFields.forEach(item => {
        const row = document.createElement("tr");
        
        const cellForm = document.createElement("td");
        cellForm.textContent = item.formIdentifier;
        cellForm.title = item.formIdentifier;
        
        const cellName = document.createElement("td");
        cellName.textContent = item.name;
        cellName.title = item.name;
        
        const cellType = document.createElement("td");
        cellType.textContent = item.type;
        cellType.title = item.type;

        row.appendChild(cellForm);
        row.appendChild(cellName);
        row.appendChild(cellType);
        listForms.appendChild(row);
      });
    }
  }

  function renderSubdomains() {
    listSubdomains.innerHTML = "";

    if (sessionData.subdomains.length === 0) {
      listSubdomains.innerHTML = createPlaceholder("No subdomains found in DOM source.");
      return;
    }

    sessionData.subdomains.forEach(sub => {
      const item = document.createElement("div");
      item.className = "list-item";
      item.textContent = sub;
      listSubdomains.appendChild(item);
    });
  }

  function renderResources() {
    listResources.innerHTML = "";

    if (sessionData.resources.length === 0) {
      listResources.innerHTML = createPlaceholder("No network endpoints or scripts loaded passively.");
      return;
    }

    sessionData.resources.forEach(url => {
      const item = document.createElement("div");
      item.className = "list-item";
      item.textContent = url;
      item.title = url;
      listResources.appendChild(item);
    });
  }

  function renderLeaks() {
    listLeaks.innerHTML = "";

    if (sessionData.leaks.length === 0) {
      listLeaks.innerHTML = createPlaceholder("No potential configuration secrets matched passively.");
      return;
    }

    sessionData.leaks.forEach(leak => {
      const card = document.createElement("div");
      card.className = "leak-card";

      const header = document.createElement("div");
      header.className = "leak-header";

      const title = document.createElement("span");
      title.className = "leak-title";
      title.textContent = leak.name;

      const source = document.createElement("span");
      source.className = "leak-source";
      source.textContent = leak.source;

      header.appendChild(title);
      header.appendChild(source);

      const valDiv = document.createElement("div");
      valDiv.className = "leak-value";
      valDiv.textContent = leak.displayValue;
      valDiv.title = "Click to log full value to console";
      valDiv.style.cursor = "pointer";
      
      // Pentester option: log full secret values on click securely inside developer tools
      valDiv.addEventListener("click", () => {
        console.log(`[ParamXray Secrets Expose] ${leak.name}:`, leak.value);
      });

      const contextDiv = document.createElement("div");
      contextDiv.className = "leak-context";
      contextDiv.textContent = leak.context;

      card.appendChild(header);
      card.appendChild(valDiv);
      card.appendChild(contextDiv);
      
      listLeaks.appendChild(card);
    });
  }

  function createPlaceholder(text) {
    return `
      <div class="empty-placeholder">
        <span class="empty-icon">🔍</span>
        <span>${text}</span>
      </div>
    `;
  }

  // 5. JSON Exporter Trigger
  btnExport.addEventListener("click", () => {
    if (sessionData.resources.length === 0 && sessionData.parameters.length === 0 && sessionData.subdomains.length === 0) {
      alert("No data collected to export. Click Analyze Page first.");
      return;
    }

    try {
      const blob = new Blob([JSON.stringify(sessionData, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      
      // Use standard download logic via link tag simulation
      const a = document.createElement("a");
      const cleanHost = sessionData.metadata.url ? new URL(sessionData.metadata.url).hostname : "export";
      
      a.href = url;
      a.download = `ParamXray_Report_${cleanHost.replace(/[^a-z0-9]/gi, '_')}.json`;
      document.body.appendChild(a);
      a.click();
      
      // Cleanup
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch(e) {
      console.error("[ParamXray Popup] Export failed:", e);
      alert("Failed to export JSON report.");
    }
  });
});
