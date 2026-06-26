/**
 * ParamXray - background.js (Service Worker)
 * Passive network request interception for Javascript, JSON, XML, TXT, and API endpoints.
 * Persists data inside chrome.storage.session by Tab ID.
 */

// Listener to intercept network requests dynamically
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Only capture requests from a valid tab (tabId >= 0)
    if (details.tabId < 0) return;

    try {
      const urlString = details.url;
      const url = new URL(urlString);
      const path = url.pathname.toLowerCase();

      // Check if URL ends with specific extensions or looks like an API call
      const isResource = /\.(js|json|xml|txt)$/i.test(path);
      const isApi = /\/api(\/v\d+)?\//i.test(path) || path.includes('/api/');

      if (isResource || isApi) {
        saveRequestForTab(details.tabId, urlString);
      }
    } catch (e) {
      console.error("[ParamXray Background] Error parsing request URL:", details.url, e);
    }
  },
  { urls: ["<all_urls>"] }
);

/**
 * Saves a discovered network endpoint into chrome.storage.session for the specific tabId.
 * Deduplicates entries to prevent unbounded storage growth.
 */
function saveRequestForTab(tabId, url) {
  const key = `network_requests_${tabId}`;
  
  chrome.storage.session.get([key], (result) => {
    let requests = result[key] || [];
    
    // Ensure uniqueness
    if (!requests.includes(url)) {
      requests.push(url);
      
      // Limit to max 500 requests per tab to avoid memory consumption
      if (requests.length > 500) {
        requests.shift();
      }

      chrome.storage.session.set({ [key]: requests }, () => {
        if (chrome.runtime.lastError) {
          console.error("[ParamXray Background] Storage error:", chrome.runtime.lastError);
        }
      });
    }
  });
}

// Clean up stored network requests when a tab is closed to prevent memory leaks
chrome.tabs.onRemoved.addListener((tabId) => {
  const key = `network_requests_${tabId}`;
  chrome.storage.session.remove(key, () => {
    if (chrome.runtime.lastError) {
      console.error("[ParamXray Background] Error removing tab data:", chrome.runtime.lastError);
    } else {
      console.log(`[ParamXray Background] Session storage cleaned for Tab ID: ${tabId}`);
    }
  });
});
