# ParamXray 🎯

ParamXray is a production-ready, highly optimized Google Chrome Extension built using **Manifest V3**. It serves as an advanced client-side passive reconnaissance and security audit tool for web penetration testers, bug hunters, and frontend engineers.

The extension continuously monitors network traffic passively and deep-scrapes the Document Object Model (DOM) of visited pages to extract query parameters, form fields, subdomains, script endpoints, and potential credential leaks using high-confidence, non-backtracking regular expressions (preventing ReDoS vulnerabilities).

---

## ⚡ Features & Modules

### 1. 🔗 Parameter & Input Extractor
* **URL Parameter Extractor**: Scans all `href` attributes in `<a>` and `<area>` tags to extract unique parameter names and sample values.
* **Form Field Extractor**: Maps out forms, identifying the `name` and `type` of input fields, dropdown menus, and textareas.

### 2. 🌐 Subdomain Extractor
* Identifies the current root domain dynamically (e.g. extracts `example.com` from `dev.sub.example.com`).
* Scrapes the page's HTML body and element attributes using optimized regular expressions to discover unique subdomains matching the base root domain.

### 3. 📦 JavaScript & Resource Tracker
* Scrapes `<script src="...">` tags to trace loaded script resources.
* Identifies inline javascript paths and resource paths ending in `.js` or `.json`.
* Passive network listeners monitor and categorize tab-specific requests for `.js`, `.json`, `.xml`, `.txt`, and active endpoints containing `/api/`.

### 4. ⚠️ Secret & Sensitive Data Finder
* Passively checks DOM text contents and script scopes for high-confidence signatures:
  * AWS Access Key IDs
  * JSON Web Tokens (JWT)
  * Slack Webhook URLs
  * Firebase & Google API Keys
  * Bearer Authorization Tokens
  * Exposed environment variables (e.g. `REACT_APP_*_SECRET`)

---

## 🎨 Cyberpunk Design Aesthetics
ParamXray features a customized, dark-themed cyberpunk user interface:
* **Background**: Sleek deep dark primary background (`#0d1117`).
* **Accents**: Neon green (`#23c55e`) and amber warning (`#f59e0b`).
* **Visuals**: Dynamic badges, interactive tab transitions, visual grid cards, custom responsive tables, and clean empty states.

---

## 📁 Repository Structure
```
ParamXray/
├── manifest.json        # Manifest V3 Extension Config
├── background.js       # Background Service Worker (Network Request Listener)
├── content.js          # DOM Scraper, Regex Matching, & Data Parser
├── popup.html          # Extension Dashboard Layout
├── popup.js            # UI Controller & Data Flow Handler
├── styles.css          # Cyberpunk Style Configs
├── icon16.png          # Toolbar Icon (16x16)
├── icon48.png          # Extensions Page Icon (48x48)
├── icon128.png         # Web Store Icon (128x128)
├── icon.png            # Original High-Resolution Icon
└── README.md           # Documentation
```

---

## 🚀 Installation & Setup

1. Clone or download this repository:
   ```bash
   git clone https://github.com/MohammadAliMehri/ParamXray.git
   ```
2. Open Google Chrome and navigate to the Extensions management page:
   * Visit `chrome://extensions/` in your browser.
3. Enable **Developer mode** in the top-right corner toggle.
4. Click the **Load unpacked** button in the top-left corner.
5. Choose the repository folder containing `manifest.json`.

---

## 🛠️ Usage
1. Click the **ParamXray** icon in your browser toolbar to open the dashboard.
2. The **Resources / APIs** tab automatically displays network endpoints captured passively.
3. Click the 🎯 **Analyze Page** button to inject the parsing logic into the current tab's active DOM and scrape deeply.
4. Browse individual tabs to inspect the scoped parameters, forms, subdomains, resources, and leaks.
5. Click 📤 **Export JSON** to download a structured, nested JSON report of the captured findings for your bug reports or audit notes.
