/**
 * ParamXray - content.js
 * Injected script executing passive reconnaissance on the page source, DOM, and active scripts.
 * Runs inside an Immediately Invoked Function Expression (IIFE).
 */
(() => {
  // Defensive check: Ensure DOM is accessible
  if (!document || !document.documentElement) {
    return {
      error: "DOM not available"
    };
  }

  // Define extraction modules
  const ParameterExtractor = {
    run() {
      const results = {
        urlParams: [],
        formInputs: []
      };

      const uniqueUrlParams = new Set();
      const uniqueFormInputs = new Set();

      // 1. Extract query params from <a> and <area> tags
      const links = document.querySelectorAll('a[href], area[href]');
      links.forEach(el => {
        try {
          const href = el.getAttribute('href');
          if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
          
          // Resolve relative URLs using document.baseURI or window.location.href
          const absoluteUrl = new URL(href, document.baseURI || window.location.href);
          
          // Scan searchParams
          if (absoluteUrl.search) {
            const params = new URLSearchParams(absoluteUrl.search);
            for (const [key, value] of params.entries()) {
              const itemKey = `${key}=${value}`;
              if (!uniqueUrlParams.has(itemKey)) {
                uniqueUrlParams.add(itemKey);
                results.urlParams.push({
                  parameter: key,
                  sampleValue: value,
                  sourceUrl: absoluteUrl.origin + absoluteUrl.pathname
                });
              }
            }
          }
        } catch (e) {
          // Silent catch to continue parsing other links defensively
        }
      });

      // 2. Parse <form> elements and get input, select, textarea name/type attributes
      const forms = document.querySelectorAll('form');
      forms.forEach((form, index) => {
        const formId = form.getAttribute('id') || form.getAttribute('name') || `index_${index}`;
        const inputs = form.querySelectorAll('input, select, textarea');
        
        inputs.forEach(input => {
          const name = input.getAttribute('name');
          const type = input.getAttribute('type') || input.tagName.toLowerCase();
          
          if (name) {
            const inputKey = `${formId}:${name}:${type}`;
            if (!uniqueFormInputs.has(inputKey)) {
              uniqueFormInputs.has(inputKey);
              results.formInputs.push({
                formIdentifier: formId,
                name: name,
                type: type
              });
            }
          }
        });
      });

      return results;
    }
  };

  const SubdomainExtractor = {
    // Safely retrieves base domain (e.g. sub.dev.example.com -> example.com)
    getRootDomain() {
      try {
        const hostname = window.location.hostname;
        const parts = hostname.split('.');
        if (parts.length <= 2) return hostname;
        
        // Simple heuristic for common double-barrel TLDs (e.g. co.uk, com.au)
        const secondToLast = parts[parts.length - 2].toLowerCase();
        const doubleBarrelTLDs = ['co', 'com', 'org', 'net', 'gov', 'edu', 'asn', 'id'];
        
        if (doubleBarrelTLDs.includes(secondToLast) && parts.length > 2) {
          return parts.slice(-3).join('.');
        }
        return parts.slice(-2).join('.');
      } catch (e) {
        return '';
      }
    },

    run() {
      const subdomains = new Set();
      const rootDomain = this.getRootDomain();
      if (!rootDomain) return [];

      try {
        // Build regex targeting any subdomains matching rootDomain
        // Escape dots in rootDomain
        const escapedRoot = rootDomain.replace(/\./g, '\\.');
        
        // Match subdomain names pattern [a-zA-Z0-9-]+\.rootDomain
        // Non-backtracking optimized regex to avoid ReDoS: [a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})*\.rootDomain
        const regexStr = `(?:[a-zA-Z0-9-]{1,63}\\.)+${escapedRoot}`;
        const subdomainRegex = new RegExp(regexStr, 'gi');

        // 1. Scan the raw page source HTML
        const htmlContent = document.documentElement.innerHTML;
        let match;
        while ((match = subdomainRegex.exec(htmlContent)) !== null) {
          subdomains.add(match[0].toLowerCase());
          // Safety cutoff to prevent loop hanging on huge payloads
          if (subdomains.size > 1000) break;
        }

        // 2. Scan all element attributes for safety
        const allElements = document.querySelectorAll('*');
        allElements.forEach(el => {
          if (subdomains.size > 1000) return;
          for (let i = 0; i < el.attributes.length; i++) {
            const attrVal = el.attributes[i].value;
            if (attrVal && attrVal.includes(rootDomain)) {
              let attrMatch;
              while ((attrMatch = subdomainRegex.exec(attrVal)) !== null) {
                subdomains.add(attrMatch[0].toLowerCase());
              }
            }
          }
        });
      } catch (e) {
        console.error("[ParamXray Content] Subdomain extractor error:", e);
      }

      return Array.from(subdomains);
    }
  };

  const ResourceTracker = {
    run() {
      const scripts = new Set();

      // 1. Scrape all script tags with 'src' attribute
      const scriptElements = document.querySelectorAll('script[src]');
      scriptElements.forEach(el => {
        const src = el.getAttribute('src');
        if (src) {
          try {
            const absUrl = new URL(src, document.baseURI || window.location.href);
            scripts.add(absUrl.href);
          } catch (e) {
            scripts.add(src);
          }
        }
      });

      // 2. Regex scan for inline script references to resources (.js or .json paths)
      // Uses a non-backtracking look-ahead or basic capture: target path patterns inside quotes
      const inlineScripts = document.querySelectorAll('script:not([src])');
      // Matches standard paths ending in .js or .json inside quotes: e.g. "/js/app.js", "config.json"
      // Optimized regex: "/?[a-zA-Z0-9_\-\.\/]+\.js(?:on)?"
      const resourceRegex = /["'](\/[a-zA-Z0-9_\-\.\/]+\.js(?:on)?)["']/gi;

      inlineScripts.forEach(script => {
        const textContent = script.textContent;
        if (!textContent) return;
        
        let match;
        while ((match = resourceRegex.exec(textContent)) !== null) {
          const path = match[1];
          try {
            const absUrl = new URL(path, document.baseURI || window.location.href);
            scripts.add(absUrl.href);
          } catch (e) {
            scripts.add(path);
          }
          // Loop limit check
          if (scripts.size > 500) break;
        }
      });

      return Array.from(scripts);
    }
  };

  const SecretFinder = {
    run() {
      const findings = [];
      const contentToScan = [];

      // Collect inline script code blocks
      const inlineScripts = document.querySelectorAll('script:not([src])');
      inlineScripts.forEach(script => {
        if (script.textContent) {
          contentToScan.push({
            source: "Inline Script",
            text: script.textContent
          });
        }
      });

      // Collect visible body text
      if (document.body && document.body.innerText) {
        contentToScan.push({
          source: "DOM Visible Text",
          text: document.body.innerText
        });
      }

      // Safe, non-backtracking high-confidence signatures
      const signatures = [
        {
          name: "AWS Access Key ID",
          regex: /\b(AKIA[0-9A-Z]{16})\b/g,
          mask: false
        },
        {
          name: "Firebase API Key / General API Key",
          // Matches standard AIzaSy pattern safely
          regex: /\b(AIzaSy[a-zA-Z0-9_\-]{33})\b/g,
          mask: true
        },
        {
          name: "JSON Web Token (JWT)",
          // Matches standard eyJ... jwt pattern safely
          regex: /\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b/g,
          mask: true
        },
        {
          name: "Slack Webhook URL",
          regex: /(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24})/g,
          mask: true
        },
        {
          name: "Generic Bearer Token",
          regex: /\bBearer\s+([a-zA-Z0-9_\-\.\~\+\/]+=*)\b/gi,
          mask: true
        },
        {
          name: "Generic Secret Environment Variable",
          regex: /\b(REACT_APP_[A-Z0-9_]*SECRET|API_KEY|CLIENT_SECRET|DB_PASSWORD)\s*[:=]\s*["']([^"']{5,})["']/gi,
          mask: true,
          customMatchIndex: 2
        }
      ];

      contentToScan.forEach(target => {
        signatures.forEach(sig => {
          let match;
          // Reset lastIndex for safety
          sig.regex.lastIndex = 0;
          
          while ((match = sig.regex.exec(target.text)) !== null) {
            let fullMatch = match[0];
            let value = sig.customMatchIndex ? match[sig.customMatchIndex] : match[1] || match[0];
            
            // Limit extraction string size to prevent memory explosion
            if (value.length > 500) {
              value = value.substring(0, 500) + "...[truncated]";
            }

            // Create masked string for output
            let displayValue = value;
            if (sig.mask && value.length > 8) {
              displayValue = value.substring(0, 4) + "..." + value.substring(value.length - 4);
            }

            // Get a snippet context
            const matchIndex = match.index;
            const startContext = Math.max(0, matchIndex - 30);
            const endContext = Math.min(target.text.length, matchIndex + fullMatch.length + 30);
            const contextSnippet = "..." + target.text.substring(startContext, endContext).replace(/\s+/g, ' ').trim() + "...";

            // Deduplicate same values found on same source
            const exists = findings.some(f => f.name === sig.name && f.value === value && f.source === target.source);
            if (!exists) {
              findings.push({
                name: sig.name,
                value: value,
                displayValue: displayValue,
                source: target.source,
                context: contextSnippet
              });
            }

            // Safety limit
            if (findings.length > 100) break;
          }
        });
      });

      return findings;
    }
  };

  // Run modules and return aggregated payload
  try {
    const paramsData = ParameterExtractor.run();
    const subdomainsData = SubdomainExtractor.run();
    const jsResources = ResourceTracker.run();
    const secretsData = SecretFinder.run();

    return {
      parameters: paramsData.urlParams,
      formFields: paramsData.formInputs,
      subdomains: subdomainsData,
      domScripts: jsResources,
      leaks: secretsData,
      scanMetadata: {
        title: document.title,
        url: window.location.href,
        timestamp: new Date().toISOString()
      }
    };
  } catch (err) {
    return {
      error: err.message || "Unknown error occurred in content.js scan"
    };
  }
})();
