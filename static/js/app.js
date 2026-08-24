/**
 * PhishGuard Security Analyzer - Frontend Client Logic
 * Handles asynchronous analysis, animated risk gauge rendering,
 * deep dive tab switching, report export, and scan history.
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const form = document.getElementById("analyzer-form");
  const urlInput = document.getElementById("url-input");
  const btnAnalyze = document.getElementById("btn-analyze");
  const btnClearInput = document.getElementById("btn-clear-input");
  const loadingContainer = document.getElementById("loading-container");
  const loadingStepTitle = document.getElementById("loading-step-title");
  const loadingStepDesc = document.getElementById("loading-step-desc");
  const errorBanner = document.getElementById("error-banner");
  const errorTitle = document.getElementById("error-title");
  const errorMessage = document.getElementById("error-message");
  const resultsSection = document.getElementById("results-section");

  // Gauge & Summary Elements
  const gaugeProgress = document.getElementById("gauge-progress");
  const scoreNumber = document.getElementById("score-number");
  const riskBadge = document.getElementById("risk-badge");
  const metaScheme = document.getElementById("meta-scheme");
  const metaDomain = document.getElementById("meta-domain");
  const metaTime = document.getElementById("meta-time");
  const targetUrlDisplay = document.getElementById("target-url-display");
  const targetSummaryText = document.getElementById("target-summary-text");
  const btnCopyReport = document.getElementById("btn-copy-report");
  const btnExportJson = document.getElementById("btn-export-json");

  // Indicators & Guidance Elements
  const recommendationsList = document.getElementById("recommendations-list");
  const indicatorsList = document.getElementById("indicators-list");
  const indicatorCounter = document.getElementById("indicator-counter");
  const positiveFactorsWrapper = document.getElementById("positive-factors-wrapper");
  const positiveFactorsList = document.getElementById("positive-factors-list");

  // Tabs Grids
  const urlMetricsGrid = document.getElementById("url-metrics-grid");
  const domainMetricsGrid = document.getElementById("domain-metrics-grid");
  const sslMetricsGrid = document.getElementById("ssl-metrics-grid");
  const dnsMetricsGrid = document.getElementById("dns-metrics-grid");

  // History Drawer Elements
  const btnToggleHistory = document.getElementById("btn-toggle-history");
  const historyDrawer = document.getElementById("history-drawer");
  const historyBackdrop = document.getElementById("history-backdrop");
  const btnCloseDrawer = document.getElementById("btn-close-drawer");
  const btnClearHistory = document.getElementById("btn-clear-history");
  const historyList = document.getElementById("history-list");
  const historyEmpty = document.getElementById("history-empty");
  const historyCountBadge = document.getElementById("history-count-badge");

  // Current analysis state cache
  let currentAssessmentData = null;
  let loadingInterval = null;

  // Max SVG arc circumference for semi-circle gauge (r=80, stroke-dasharray = pi * 80 ~= 251.32)
  const GAUGE_CIRCUMFERENCE = 251.32;

  // ==========================================
  // 1. Initial Setup & Event Listeners
  // ==========================================

  // URL Input clear button visibility
  urlInput.addEventListener("input", () => {
    btnClearInput.style.display = urlInput.value.length > 0 ? "block" : "none";
  });

  btnClearInput.addEventListener("click", () => {
    urlInput.value = "";
    urlInput.focus();
    btnClearInput.style.display = "none";
  });

  // Preset Sample buttons
  document.querySelectorAll(".btn-preset").forEach((btn) => {
    btn.addEventListener("click", () => {
      const presetUrl = btn.getAttribute("data-url");
      if (presetUrl) {
        urlInput.value = presetUrl;
        btnClearInput.style.display = "block";
        executeAnalysis(presetUrl);
      }
    });
  });

  // Form Submission
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;
    executeAnalysis(url);
  });

  // Tab Switching
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const targetTabId = btn.getAttribute("data-tab");
      const targetPane = document.getElementById(targetTabId);
      if (targetPane) {
        targetPane.classList.add("active");
      }
    });
  });

  // History Drawer Toggles
  btnToggleHistory.addEventListener("click", openHistoryDrawer);
  btnCloseDrawer.addEventListener("click", closeHistoryDrawer);
  historyBackdrop.addEventListener("click", closeHistoryDrawer);
  btnClearHistory.addEventListener("click", handleClearHistory);

  // Copy & Export Buttons
  btnCopyReport.addEventListener("click", copyAssessmentToClipboard);
  btnExportJson.addEventListener("click", exportAssessmentJson);

  // Load initial history count on page load
  loadHistoryRecords();

  // ==========================================
  // 2. Analysis Execution & API Communication
  // ==========================================

  async function executeAnalysis(url) {
    // Reset UI states
    hideError();
    resultsSection.style.display = "none";
    startLoadingAnimation();
    btnAnalyze.disabled = true;

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: url }),
      });

      const data = await response.json();

      if (!response.ok || data.status !== "success") {
        const errorMsg = data.message || "Failed to analyze the specified URL.";
        const errorHead = data.error_type === "SSRF_SECURITY_BLOCK" ? "Security Policy Alert (SSRF Blocked)" : "Analysis Error";
        showError(errorHead, errorMsg);
        return;
      }

      // Success: render assessment report
      currentAssessmentData = data;
      renderAssessment(data);
      loadHistoryRecords(); // refresh history drawer
    } catch (err) {
      showError("Connection Failure", "Unable to connect to the backend security analysis engine. Please verify the server is running.");
    } finally {
      stopLoadingAnimation();
      btnAnalyze.disabled = false;
    }
  }

  // ==========================================
  // 3. UI Rendering & Score Visuals
  // ==========================================

  function renderAssessment(data) {
    // Show results container
    resultsSection.style.display = "block";
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });

    // Animate Gauge & Score Number
    animateScoreGauge(data.risk_score, data.risk_tier, data.badge_color);

    // Metadata Tags
    metaScheme.textContent = (data.url_analysis.scheme || "HTTPS").toUpperCase();
    metaDomain.textContent = data.domain || data.hostname;
    metaTime.textContent = new Date(data.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

    // Target URL & Summary
    targetUrlDisplay.textContent = data.sanitized_url;
    targetSummaryText.textContent = data.summary;

    // Actionable Recommendations
    recommendationsList.innerHTML = "";
    if (data.recommendations && data.recommendations.length > 0) {
      data.recommendations.forEach((rec) => {
        const li = document.createElement("li");
        li.textContent = rec;
        recommendationsList.appendChild(li);
      });
    }

    // Security Indicators List
    indicatorsList.innerHTML = "";
    indicatorCounter.textContent = `${data.indicator_count} Detected`;

    if (data.indicators && data.indicators.length > 0) {
      data.indicators.forEach((ind) => {
        const item = document.createElement("div");
        item.className = "indicator-item";

        const deltaClass = `delta-${ind.severity || "medium"}`;

        item.innerHTML = `
          <div class="indicator-item-header">
            <div class="indicator-item-left">
              <span class="indicator-score-delta ${deltaClass}">+${ind.points} Risk</span>
              <span class="indicator-name">${escapeHtml(ind.name)}</span>
            </div>
            <span class="indicator-category">${escapeHtml(ind.category)}</span>
          </div>
          <p class="indicator-explanation">${escapeHtml(ind.explanation)}</p>
          ${ind.evidence ? `<div class="indicator-evidence">Evidence: ${escapeHtml(ind.evidence)}</div>` : ""}
        `;
        indicatorsList.appendChild(item);
      });
    } else {
      indicatorsList.innerHTML = `
        <div style="padding: 16px; background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 8px; color: #a7f3d0; font-size: 0.88rem;">
          ✨ No high-risk phishing indicators or deceptive patterns detected in the analyzed components.
        </div>
      `;
    }

    // Positive Trust Factors
    if (data.positive_factors && data.positive_factors.length > 0) {
      positiveFactorsWrapper.style.display = "block";
      positiveFactorsList.innerHTML = "";
      data.positive_factors.forEach((factor) => {
        const item = document.createElement("div");
        item.className = "positive-factor-item";
        item.innerHTML = `<strong>✔ ${escapeHtml(factor.name)}:</strong> ${escapeHtml(factor.detail)}`;
        positiveFactorsList.appendChild(item);
      });
    } else {
      positiveFactorsWrapper.style.display = "none";
    }

    // Render Deep-Dive Tabs
    renderURLTab(data.url_analysis);
    renderDomainTab(data.domain_analysis);
    renderSSLTab(data.ssl_analysis);
    renderDNSTab(data.dns_analysis);
  }

  function animateScoreGauge(targetScore, riskTier, badgeColor) {
    // Risk Badge Text and Style
    riskBadge.className = `risk-badge badge-${riskTier}`;
    riskBadge.textContent = riskTier.toUpperCase().replace("_", " ");

    if (riskTier === "safe") riskBadge.textContent = "LIKELY SAFE";
    if (riskTier === "suspicious") riskBadge.textContent = "SUSPICIOUS";
    if (riskTier === "high") riskBadge.textContent = "HIGH RISK";
    if (riskTier === "critical") riskBadge.textContent = "VERY HIGH RISK";

    // SVG Stroke calculation (dashoffset from 251.3 down based on score)
    const targetOffset = GAUGE_CIRCUMFERENCE - (targetScore / 100) * GAUGE_CIRCUMFERENCE;
    gaugeProgress.style.stroke = badgeColor;
    gaugeProgress.style.transition = "stroke-dashoffset 1.2s cubic-bezier(0.16, 1, 0.3, 1)";
    gaugeProgress.style.strokeDashoffset = targetOffset;

    // Numerical counter animation
    let current = 0;
    const duration = 1000; // ms
    const stepTime = 20;
    const steps = duration / stepTime;
    const increment = targetScore / steps;

    scoreNumber.textContent = "0";
    const timer = setInterval(() => {
      current += increment;
      if (current >= targetScore) {
        scoreNumber.textContent = targetScore;
        clearInterval(timer);
      } else {
        scoreNumber.textContent = Math.round(current);
      }
    }, stepTime);
  }

  // ==========================================
  // 4. Tab Grids Population
  // ==========================================

  function renderURLTab(urlData) {
    const m = urlData.metrics || {};
    const h = urlData.heuristics || {};

    const cells = [
      { label: "Registered Domain", value: urlData.registered_domain || "N/A", highlight: true },
      { label: "Hostname", value: urlData.hostname || "N/A" },
      { label: "Subdomains", value: urlData.subdomain ? `${urlData.subdomain} (${m.subdomain_count})` : "None (0)" },
      { label: "Total URL Length", value: `${m.url_length} chars` },
      { label: "Domain Length", value: `${m.domain_length} chars` },
      { label: "IP Host Address", value: h.is_ip_address ? "Yes (High Risk)" : "No" },
      { label: "Punycode / Homograph", value: h.is_punycode ? "Yes (Detected)" : "No" },
      { label: "Domain Entropy", value: `${m.domain_entropy} (Randomness Index)` },
      { label: "Path Entropy", value: `${m.path_entropy}` },
      { label: "Dot Count (Domain)", value: `${m.dot_count_domain}` },
      { label: "Hyphen Count (Domain)", value: `${m.hyphen_count_domain}` },
      { label: "Suspicious TLD", value: h.has_suspicious_tld ? `Yes (.${h.suspicious_tld})` : "Standard" },
      { label: "Brand Spoofing", value: h.brand_spoofing_detected ? `Spoofs ${h.impersonated_brand}` : "None detected" },
      { label: "Keywords in Domain", value: h.found_keywords_domain.length > 0 ? h.found_keywords_domain.join(", ") : "None" },
      { label: "Suspicious Extension", value: h.has_suspicious_extension ? "Detected in path" : "None" },
    ];

    urlMetricsGrid.innerHTML = cells.map(createDataCell).join("");
  }

  function renderDomainTab(domainData) {
    const cells = [
      { label: "Domain Name", value: domainData.domain_name || "N/A", highlight: true },
      { label: "Registrar", value: domainData.registrar || "Unavailable" },
      { label: "Creation Date", value: domainData.creation_date || "Not disclosed" },
      { label: "Expiration Date", value: domainData.expiration_date || "Not disclosed" },
      { label: "Domain Age", value: domainData.age_text || "Unknown" },
      { label: "Days Until Expiration", value: domainData.days_until_expiration !== null ? `${domainData.days_until_expiration} days` : "Unknown" },
      { label: "Privacy Protection", value: domainData.is_privacy_protected ? "Active / Hidden (Proxy)" : "Public / Standard" },
      { label: "WHOIS Status", value: domainData.status_list.length > 0 ? domainData.status_list[0] : "Active" },
    ];

    domainMetricsGrid.innerHTML = cells.map(createDataCell).join("");
  }

  function renderSSLTab(sslData) {
    const cells = [
      { label: "HTTPS Protocol", value: sslData.is_https_requested ? "Enabled" : "Disabled (Plain HTTP)", highlight: true },
      { label: "SSL Certificate Status", value: sslData.has_ssl ? (sslData.status === "valid" ? "Valid" : "Warning / Untrusted") : "No Certificate Found" },
      { label: "Issuer Organization", value: sslData.issuer || "None" },
      { label: "Subject Common Name", value: sslData.subject_cn || "None" },
      { label: "Valid From", value: sslData.valid_from || "N/A" },
      { label: "Valid Until", value: sslData.valid_to || "N/A" },
      { label: "Days Remaining", value: sslData.days_remaining !== null ? `${sslData.days_remaining} days` : "N/A" },
      { label: "Hostname Match", value: sslData.hostname_match ? "Matches Certificate" : "Mismatch / Unverified" },
      { label: "Self-Signed", value: sslData.is_self_signed ? "Yes (Self-Signed CA)" : "No (Issued by Authority)" },
      { label: "TLS Version", value: sslData.tls_version || "N/A" },
      { label: "Alternative Names (SANs)", value: sslData.san_list.length > 0 ? `${sslData.san_list.length} names configured` : "None" },
    ];

    sslMetricsGrid.innerHTML = cells.map(createDataCell).join("");
  }

  function renderDNSTab(dnsData) {
    const aRecords = dnsData.a_records && dnsData.a_records.length > 0 ? dnsData.a_records.join(", ") : "None";
    const aaaaRecords = dnsData.aaaa_records && dnsData.aaaa_records.length > 0 ? dnsData.aaaa_records.join(", ") : "None";
    const mxRecords = dnsData.mx_records && dnsData.mx_records.length > 0 ? dnsData.mx_records.join(", ") : "None configured";
    const nsRecords = dnsData.ns_records && dnsData.ns_records.length > 0 ? dnsData.ns_records.slice(0, 3).join(", ") : "None";

    const cells = [
      { label: "DNS Resolution Status", value: dnsData.resolved ? "Resolved Successfully" : "Lookup Failed", highlight: true },
      { label: "IPv4 Addresses (A)", value: aRecords },
      { label: "IPv6 Addresses (AAAA)", value: aaaaRecords },
      { label: "Mail Exchangers (MX)", value: mxRecords },
      { label: "Authoritative Nameservers", value: nsRecords },
      { label: "Direct IP Mode", value: dnsData.is_ip_direct ? "Yes (No DNS required)" : "No (Standard DNS)" },
    ];

    dnsMetricsGrid.innerHTML = cells.map(createDataCell).join("");
  }

  function createDataCell(cell) {
    return `
      <div class="data-cell">
        <div class="data-label">${escapeHtml(cell.label)}</div>
        <div class="data-value ${cell.highlight ? "data-value-highlight" : ""}">${escapeHtml(cell.value)}</div>
      </div>
    `;
  }

  // ==========================================
  // 5. History Drawer & Persistence
  // ==========================================

  async function loadHistoryRecords() {
    try {
      const response = await fetch("/api/history?limit=25");
      const data = await response.json();
      if (data.status === "success" && data.history) {
        historyCountBadge.textContent = data.history.length;
        renderHistoryList(data.history);
      }
    } catch (err) {
      console.warn("Could not load scan history:", err);
    }
  }

  function renderHistoryList(items) {
    if (!items || items.length === 0) {
      historyList.innerHTML = "";
      historyEmpty.style.display = "block";
      return;
    }

    historyEmpty.style.display = "none";
    historyList.innerHTML = "";

    items.forEach((item) => {
      const div = document.createElement("div");
      div.className = "history-item";
      const badgeClass = `badge-${item.risk_tier || "safe"}`;

      div.innerHTML = `
        <div class="history-item-top">
          <span class="history-score-tag ${badgeClass}">${item.risk_score}/100 • ${escapeHtml(item.risk_level)}</span>
          <span class="history-time">${new Date(item.timestamp).toLocaleDateString()}</span>
        </div>
        <div class="history-url">${escapeHtml(item.url)}</div>
        <div class="history-indicator-snippet">${escapeHtml(item.top_indicator || "Scan completed")}</div>
      `;

      div.addEventListener("click", async () => {
        closeHistoryDrawer();
        try {
          const res = await fetch(`/api/history/${item.id}`);
          const resData = await res.json();
          if (resData.status === "success" && resData.report) {
            currentAssessmentData = resData.report;
            urlInput.value = resData.report.submitted_url || item.url;
            btnClearInput.style.display = "block";
            renderAssessment(resData.report);
          }
        } catch (e) {
          showError("Error", "Could not load selected report from history.");
        }
      });

      historyList.appendChild(div);
    });
  }

  async function handleClearHistory() {
    if (!confirm("Are you sure you want to clear your local analysis history?")) return;
    try {
      const response = await fetch("/api/history", { method: "DELETE" });
      const data = await response.json();
      if (data.status === "success") {
        historyCountBadge.textContent = "0";
        historyList.innerHTML = "";
        historyEmpty.style.display = "block";
      }
    } catch (e) {
      alert("Failed to clear history.");
    }
  }

  function openHistoryDrawer() {
    loadHistoryRecords();
    historyDrawer.classList.add("open");
  }

  function closeHistoryDrawer() {
    historyDrawer.classList.remove("open");
  }

  // ==========================================
  // 6. Report Export & Copy
  // ==========================================

  function copyAssessmentToClipboard() {
    if (!currentAssessmentData) return;

    const indText = currentAssessmentData.indicators
      .map((ind) => `  * [${ind.severity.toUpperCase()}] +${ind.points} Risk: ${ind.name} - ${ind.explanation}`)
      .join("\n");

    const report = [
      `=======================================================`,
      `PHISHGUARD SECURITY ASSESSMENT REPORT`,
      `=======================================================`,
      `Target URL    : ${currentAssessmentData.sanitized_url}`,
      `Domain / Host : ${currentAssessmentData.domain || currentAssessmentData.hostname}`,
      `Assessment Date: ${currentAssessmentData.timestamp}`,
      `Risk Score    : ${currentAssessmentData.risk_score} / 100`,
      `Risk Level    : ${currentAssessmentData.risk_level}`,
      `Summary       : ${currentAssessmentData.summary}`,
      ``,
      `KEY SECURITY INDICATORS:`,
      indText || `  * No high-risk phishing indicators detected.`,
      ``,
      `RECOMMENDATIONS:`,
      currentAssessmentData.recommendations.map((r) => `  * ${r}`).join("\n"),
      ``,
      `DISCLAIMER:`,
      currentAssessmentData.disclaimer,
      `=======================================================`,
    ].join("\n");

    navigator.clipboard.writeText(report).then(() => {
      const originalText = btnCopyReport.innerHTML;
      btnCopyReport.innerHTML = `✔ Copied!`;
      setTimeout(() => {
        btnCopyReport.innerHTML = originalText;
      }, 2000);
    }).catch(() => {
      alert("Unable to copy to clipboard.");
    });
  }

  function exportAssessmentJson() {
    if (!currentAssessmentData) return;
    const blob = new Blob([JSON.stringify(currentAssessmentData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const domain = (currentAssessmentData.domain || "assessment").replace(/[^a-zA-Z0-9.-]/g, "_");
    a.href = url;
    a.download = `phishguard_${domain}_report.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ==========================================
  // 7. Loading and Error Helpers
  // ==========================================

  function startLoadingAnimation() {
    loadingContainer.style.display = "flex";
    const steps = [
      { title: "Enforcing SSRF & Input Security...", desc: "Validating hostname, checking cloud metadata endpoints, and sanitizing URL structure." },
      { title: "Inspecting URL Characteristics...", desc: "Evaluating lexical metrics, subdomains, homograph glyphs, and brand keywords." },
      { title: "Performing Safe DNS & WHOIS Lookups...", desc: "Inspecting authoritative records, nameservers, and domain creation timeline." },
      { title: "Analyzing SSL/TLS Certificate...", desc: "Inspecting certificate validity, issuer authority, and expiration window." },
      { title: "Computing Explainable Risk Score...", desc: "Running transparent 0–100 heuristic scoring engine." },
    ];

    let currentStep = 0;
    loadingStepTitle.textContent = steps[0].title;
    loadingStepDesc.textContent = steps[0].desc;

    loadingInterval = setInterval(() => {
      currentStep = (currentStep + 1) % steps.length;
      loadingStepTitle.textContent = steps[currentStep].title;
      loadingStepDesc.textContent = steps[currentStep].desc;
    }, 700);
  }

  function stopLoadingAnimation() {
    if (loadingInterval) {
      clearInterval(loadingInterval);
      loadingInterval = null;
    }
    loadingContainer.style.display = "none";
  }

  function showError(title, message) {
    errorTitle.textContent = title;
    errorMessage.textContent = message;
    errorBanner.style.display = "flex";
    errorBanner.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function hideError() {
    errorBanner.style.display = "none";
  }

  function escapeHtml(str) {
    if (!str && str !== 0) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
