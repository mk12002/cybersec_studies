const DATA_FILES = {
  certifications: "data/certifications.json",
  countries: "data/countries.json",
  scores: "data/cert_country_scores.json",
  paths: "data/learning_paths.json",
};

const LEVEL_RANK = {
  beginner: 1,
  intermediate: 2,
  advanced: 3,
};

const DOMAIN_LABELS = {
  appsec: "AppSec",
  cloudsec: "Cloud Security",
  soc: "SOC and Detection",
  governance: "Governance and Risk",
  offensive: "Offensive Security",
  mlsec: "ML Security",
  privacy: "Privacy",
  fundamentals: "Fundamentals",
  architecture: "Architecture",
  compliance: "Compliance",
  detection: "Detection",
  operations: "Operations",
  "incident-response": "Incident Response",
  forensics: "Forensics",
  pentest: "Penetration Testing",
  "web-security": "Web Security",
  platform: "Platform Security",
  audit: "Audit",
  management: "Management",
  risk: "Risk",
  engineering: "Engineering",
  implementation: "Implementation",
  consulting: "Consulting",
  leadership: "Leadership",
  cloud: "Cloud",
  "blue-team": "Blue Team",
  "red-team": "Red Team",
  "threat-hunting": "Threat Hunting",
};

const DOMAIN_ALIAS = {
  devsecops: "cloudsec",
  "secure-sdlc": "appsec",
  detection: "soc",
  risk: "governance",
  compliance: "governance",
  audit: "governance",
  management: "governance",
  architecture: "cloudsec",
  platform: "cloudsec",
  fundamentals: "soc",
};

let cache = null;

document.addEventListener("DOMContentLoaded", () => {
  init().catch((err) => {
    console.error(err);
    document.body.innerHTML = `<main style=\"padding:1rem;color:#fff;font-family:sans-serif\">Failed to load module data. Check console for details.</main>`;
  });
});

async function init() {
  const data = await loadData();
  const page = document.body.dataset.page;

  if (page === "dashboard") initDashboard(data);
  if (page === "country") initCountryPage(data);
  if (page === "compare") initComparePage(data);
  if (page === "weekly-brief") initWeeklyBriefPage(data);
}

async function loadData() {
  if (cache) return cache;

  const [certRes, countryRes, scoreRes, pathRes] = await Promise.all([
    fetch(DATA_FILES.certifications),
    fetch(DATA_FILES.countries),
    fetch(DATA_FILES.scores),
    fetch(DATA_FILES.paths),
  ]);

  const [certificationsJson, countriesJson, scoresJson, pathsJson] = await Promise.all([
    certRes.json(),
    countryRes.json(),
    scoreRes.json(),
    pathRes.json(),
  ]);

  const certifications = certificationsJson.certifications || [];
  const countries = countriesJson.countries || [];
  const scores = scoresJson.scores || [];
  const roleProfiles = pathsJson.roleProfiles || [];
  const learningPaths = pathsJson.learningPaths || [];
  const weeklyTemplates = pathsJson.weeklyBriefTemplates || [];
  const resourceAnchors = pathsJson.resourceAnchors || {};

  cache = {
    certifications,
    countries,
    scores,
    roleProfiles,
    learningPaths,
    weeklyTemplates,
    resourceAnchors,
    certById: indexBy(certifications, "id"),
    countryById: indexBy(countries, "id"),
    scoreByCert: indexBy(scores, "certId"),
    roleById: indexBy(roleProfiles, "id"),
  };

  return cache;
}

function initDashboard(data) {
  const countryFilter = document.getElementById("countryFilter");
  const roleFilter = document.getElementById("roleFilter");
  const levelFilter = document.getElementById("levelFilter");
  const budgetFilter = document.getElementById("budgetFilter");

  const cardsEl = document.getElementById("dashboardCards");
  const bestPathEl = document.getElementById("bestPathCards");
  const trendsEl = document.getElementById("trendSnapshot");
  const quickEl = document.getElementById("quickRecommendations");
  const countEl = document.getElementById("resultCount");
  const pathContextEl = document.getElementById("pathContext");

  populateCountrySelect(countryFilter, data.countries);
  populateRoleSelect(roleFilter, data.roleProfiles);

  const params = new URLSearchParams(window.location.search);
  ensureSelectValue(countryFilter, params.get("country"), "india");
  ensureSelectValue(roleFilter, params.get("role"), data.roleProfiles[0]?.id || "");

  const render = () => {
    const countryId = countryFilter.value;
    const roleId = roleFilter.value;
    const level = levelFilter.value;
    const budget = budgetFilter.value === "all" ? Infinity : Number(budgetFilter.value);

    const country = data.countryById[countryId] || data.countries[0];
    const role = data.roleById[roleId] || data.roleProfiles[0];

    if (!country || !role) return;

    if (countryFilter.value !== country.id) {
      countryFilter.value = country.id;
    }
    if (roleFilter.value !== role.id) {
      roleFilter.value = role.id;
    }

    const ranked = data.certifications
      .filter((cert) => cert.costUSD <= budget)
      .filter((cert) => isLevelMatch(cert.level, level))
      .map((cert) => {
        const countryScore = getCountryScore(data, cert.id, country.id);
        const relevance = getRoleRelevance(cert, role);
        const composite = scoreCertification(cert, countryScore, relevance);
        return { cert, countryScore, relevance, composite };
      })
      .sort((a, b) => b.composite - a.composite);

    countEl.textContent = `${ranked.length} matches`;
    pathContextEl.textContent = `${country.name} | ${role.label}`;

    cardsEl.innerHTML = ranked.slice(0, 12).map((item) => renderCertCard(item)).join("");
    if (!ranked.length) {
      cardsEl.innerHTML = '<p class="empty">No certifications match the selected filters.</p>';
    }

    bestPathEl.innerHTML = renderCountryPath(country, data.certById);
    trendsEl.innerHTML = renderDemandBars(country.domainDemand);

    const top = ranked[0];
    const quickPoints = buildQuickRecommendations({ country, role, level, budget, top, ranked });
    quickEl.innerHTML = quickPoints.map((line) => `<li>${escapeHtml(line)}</li>`).join("");

    const nextParams = new URLSearchParams({ country: country.id, role: role.id });
    history.replaceState(null, "", `index.html?${nextParams.toString()}`);
  };

  [countryFilter, roleFilter, levelFilter, budgetFilter].forEach((el) => {
    el.addEventListener("change", render);
  });

  render();
}

function initCountryPage(data) {
  const countrySelect = document.getElementById("countrySelectDeep");
  const summaryEl = document.getElementById("countrySummary");
  const demandEl = document.getElementById("countryDemand");
  const pathEl = document.getElementById("countryPathCards");
  const notesEl = document.getElementById("countryNotes");
  const employersEl = document.getElementById("countryEmployers");
  const heatmapBody = document.getElementById("countryHeatmapBody");

  populateCountrySelect(countrySelect, data.countries);

  const params = new URLSearchParams(window.location.search);
  ensureSelectValue(countrySelect, params.get("country"), "india");

  const render = () => {
    const country = data.countryById[countrySelect.value] || data.countries[0];
    if (!country) return;

    if (countrySelect.value !== country.id) {
      countrySelect.value = country.id;
    }

    summaryEl.innerHTML = `
      <div class="country-summary-box">
        <h2>${escapeHtml(country.name)}</h2>
        <p>${escapeHtml(country.hiringSignal)}</p>
        <p class="mono">Visa/Work Context: ${escapeHtml(country.visaWorkContext)}</p>
        <div class="summary-grid">
          <article><h4>Entry</h4><strong>${escapeHtml(country.salaryBands.entry)}</strong></article>
          <article><h4>Mid</h4><strong>${escapeHtml(country.salaryBands.mid)}</strong></article>
          <article><h4>Senior</h4><strong>${escapeHtml(country.salaryBands.senior)}</strong></article>
        </div>
      </div>
    `;

    demandEl.innerHTML = renderDemandBars(country.domainDemand);
    pathEl.innerHTML = renderCountryPath(country, data.certById);

    notesEl.innerHTML = country.marketNotes.map((note) => `<li>${escapeHtml(note)}</li>`).join("");
    employersEl.innerHTML = country.topEmployers.map((employer) => `<span class="tag">${escapeHtml(employer)}</span>`).join("");

    const heatRows = data.certifications
      .map((cert) => ({
        cert,
        score: getCountryScore(data, cert.id, country.id),
      }))
      .sort((a, b) => b.score - a.score || b.cert.roiBase - a.cert.roiBase)
      .slice(0, 14);

    heatmapBody.innerHTML = heatRows
      .map(({ cert, score }) => {
        const tracks = cert.tracks.slice(0, 2).map((t) => DOMAIN_LABELS[t] || t).join(" / ");
        return `
          <tr>
            <td>${escapeHtml(cert.name)}</td>
            <td>${escapeHtml(tracks)}</td>
            <td>${renderScorePill(score)}</td>
            <td>${renderScorePill(cert.roiBase)}</td>
            <td>$${cert.costUSD}</td>
          </tr>
        `;
      })
      .join("");

    const nextParams = new URLSearchParams({ country: country.id });
    history.replaceState(null, "", `country.html?${nextParams.toString()}`);
  };

  countrySelect.addEventListener("change", render);
  render();
}

function initComparePage(data) {
  const countryEl = document.getElementById("compareCountry");
  const roleEl = document.getElementById("compareRole");
  const certsEl = document.getElementById("compareCerts");
  const runBtn = document.getElementById("runCompareBtn");
  const tableBody = document.getElementById("compareBody");
  const insightsEl = document.getElementById("compareInsights");

  populateCountrySelect(countryEl, data.countries);
  populateRoleSelect(roleEl, data.roleProfiles);

  certsEl.innerHTML = data.certifications
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((cert) => `<option value="${cert.id}">${escapeHtml(cert.name)} ($${cert.costUSD})</option>`)
    .join("");

  ensureSelectValue(countryEl, "india", data.countries[0]?.id || "");
  ensureSelectValue(roleEl, data.roleProfiles[0]?.id || "", data.roleProfiles[0]?.id || "");

  ["aws-security", "az-500", "cissp"].forEach((id) => {
    const option = certsEl.querySelector(`option[value=\"${id}\"]`);
    if (option) option.selected = true;
  });

  const render = () => {
    const selectedIds = Array.from(certsEl.selectedOptions).map((opt) => opt.value);
    const country = data.countryById[countryEl.value] || data.countries[0];
    const role = data.roleById[roleEl.value] || data.roleProfiles[0];

    if (!country || !role) return;

    if (countryEl.value !== country.id) {
      countryEl.value = country.id;
    }
    if (roleEl.value !== role.id) {
      roleEl.value = role.id;
    }

    if (selectedIds.length < 2 || selectedIds.length > 4) {
      tableBody.innerHTML = '<tr><td colspan="8" class="empty">Select 2 to 4 certifications to compare.</td></tr>';
      insightsEl.innerHTML = "<li>Select at least 2 and at most 4 certifications for meaningful comparison.</li>";
      return;
    }

    const compared = selectedIds
      .map((id) => data.certById[id])
      .filter(Boolean)
      .map((cert) => {
        const countryScore = getCountryScore(data, cert.id, country.id);
        const relevance = getRoleRelevance(cert, role);
        const composite = scoreCertification(cert, countryScore, relevance);
        return { cert, countryScore, relevance, composite };
      })
      .sort((a, b) => b.composite - a.composite);

    tableBody.innerHTML = compared
      .map((item) => {
        const cert = item.cert;
        const compositeRoi = toFivePointScale(item.composite);
        return `
          <tr>
            <td>${escapeHtml(cert.name)}</td>
            <td>$${cert.costUSD}</td>
            <td>${cert.effortHoursMin}-${cert.effortHoursMax}h</td>
            <td>${escapeHtml(cert.prerequisites)}</td>
            <td>${escapeHtml(cert.renewal)}</td>
            <td>${renderScorePill(item.relevance)}</td>
            <td>${renderScorePill(item.countryScore)}</td>
            <td>${renderScorePill(compositeRoi)}</td>
          </tr>
        `;
      })
      .join("");

    const top = compared[0];
    const lowEffort = [...compared].sort((a, b) => a.cert.effortHoursMin - b.cert.effortHoursMin)[0];
    const longTerm = [...compared].sort((a, b) => b.cert.globalRecognition - a.cert.globalRecognition)[0];

    const insights = [
      `Best immediate fit for ${role.label} in ${country.name}: ${top.cert.name}.`,
      `Fastest to execute: ${lowEffort.cert.name} (${lowEffort.cert.effortHoursMin}-${lowEffort.cert.effortHoursMax} hours).`,
      `Best long-term global mobility signal: ${longTerm.cert.name}.`,
      "Use one practical cert + one strategic cert combo to balance interview conversion and long-term positioning.",
    ];

    insightsEl.innerHTML = insights.map((line) => `<li>${escapeHtml(line)}</li>`).join("");
  };

  runBtn.addEventListener("click", render);
  countryEl.addEventListener("change", render);
  roleEl.addEventListener("change", render);
  render();
}

function initWeeklyBriefPage(data) {
  const countryEl = document.getElementById("briefCountry");
  const roleEl = document.getElementById("briefRole");
  const levelEl = document.getElementById("briefLevel");
  const hoursEl = document.getElementById("briefHours");
  const templateEl = document.getElementById("briefTemplate");
  const generateBtn = document.getElementById("generateBriefBtn");

  const summaryEl = document.getElementById("briefSummary");
  const certEl = document.getElementById("briefCertPriorities");
  const resourcesEl = document.getElementById("briefResources");
  const planBody = document.getElementById("briefPlanBody");

  populateCountrySelect(countryEl, data.countries);
  populateRoleSelect(roleEl, data.roleProfiles);

  templateEl.innerHTML = data.weeklyTemplates
    .map((t) => `<option value="${t.id}">${escapeHtml(t.label)}</option>`)
    .join("");

  ensureSelectValue(countryEl, "india", data.countries[0]?.id || "");
  ensureSelectValue(roleEl, "ml-security-engineer", data.roleProfiles[0]?.id || "");

  const render = () => {
    const country = data.countryById[countryEl.value] || data.countries[0];
    const role = data.roleById[roleEl.value] || data.roleProfiles[0];
    const template = data.weeklyTemplates.find((t) => t.id === templateEl.value) || data.weeklyTemplates[0];
    if (!country || !role || !template) return;

    if (countryEl.value !== country.id) {
      countryEl.value = country.id;
    }
    if (roleEl.value !== role.id) {
      roleEl.value = role.id;
    }

    const level = levelEl.value;
    const weeklyHours = Math.max(4, Number(hoursEl.value) || 12);
    const weeklyMinutes = weeklyHours * 60;

    const levelPath = country.recommendedPaths[level] || [];
    const roleCerts = role.coreCerts || [];
    const certPriorityIds = unique([...levelPath, ...roleCerts]).slice(0, 4);
    const certPriority = certPriorityIds.map((id) => data.certById[id]).filter(Boolean);

    summaryEl.innerHTML = `
      <p><strong>Market:</strong> ${escapeHtml(country.name)}</p>
      <p><strong>Role:</strong> ${escapeHtml(role.label)}</p>
      <p><strong>Weekly Target:</strong> ${weeklyHours} hours (${weeklyMinutes} minutes)</p>
      <p class="mono">${escapeHtml(country.hiringSignal)}</p>
    `;

    certEl.innerHTML = certPriority
      .map((cert) => `<li>${escapeHtml(cert.name)} - ${escapeHtml(cert.notes)}</li>`)
      .join("");

    const focusDomains = normalizeDomains(role.focusDomains);
    const resourceSet = [];
    focusDomains.forEach((domain) => {
      const anchors = data.resourceAnchors[domain] || [];
      anchors.forEach((item) => resourceSet.push(item));
    });

    resourcesEl.innerHTML = unique(resourceSet)
      .slice(0, 8)
      .map((resource) => `<li>${escapeHtml(resource)}</li>`)
      .join("");

    const distribution = template.split;
    const activityMinutes = {
      labs: Math.round(weeklyMinutes * (distribution.labs || 0)),
      build: Math.round(weeklyMinutes * (distribution.build || 0)),
      reading: Math.round(weeklyMinutes * (distribution.reading || 0)),
      writeup: Math.round(weeklyMinutes * (distribution.writeup || 0)),
      review: Math.round(weeklyMinutes * (distribution.review || 0)),
    };

    const dayActivities = ["reading", "labs", "build", "labs", "writeup", "review", "labs"];
    const dayPlan = template.dayPlan || [];

    planBody.innerHTML = dayActivities
      .map((activity, idx) => {
        const day = idx + 1;
        const base = Math.max(35, Math.round((activityMinutes[activity] || 60) / (activity === "labs" ? 3 : 1)));
        const deliverable = role.targetArtifacts[idx % role.targetArtifacts.length] || "Evidence note";

        return `
          <tr>
            <td>Day ${day}</td>
            <td>${escapeHtml(dayPlan[idx] || "Focused study block")}</td>
            <td>${base}</td>
            <td>${escapeHtml(deliverable)}</td>
          </tr>
        `;
      })
      .join("");
  };

  generateBtn.addEventListener("click", render);
  [countryEl, roleEl, levelEl, templateEl].forEach((el) => el.addEventListener("change", render));
  render();
}

function populateCountrySelect(el, countries) {
  if (!el) return;
  el.innerHTML = countries
    .map((country) => `<option value="${country.id}">${escapeHtml(country.name)}</option>`)
    .join("");
}

function populateRoleSelect(el, roles) {
  if (!el) return;
  el.innerHTML = roles
    .map((role) => `<option value="${role.id}">${escapeHtml(role.label)}</option>`)
    .join("");
}

function ensureSelectValue(selectEl, preferredValue, fallbackValue) {
  if (!selectEl) return "";

  const values = Array.from(selectEl.options).map((opt) => opt.value);
  let next = preferredValue;

  if (!next || !values.includes(next)) {
    next = fallbackValue;
  }

  if (!next || !values.includes(next)) {
    next = values[0] || "";
  }

  selectEl.value = next;
  return next;
}

function renderCertCard(item) {
  const cert = item.cert;
  const tracks = cert.tracks.slice(0, 3).map((track) => `<span class="tag">${escapeHtml(DOMAIN_LABELS[track] || track)}</span>`).join("");

  return `
    <article class="cert-card">
      <h4>${escapeHtml(cert.name)}</h4>
      <p>${escapeHtml(cert.vendor)} | ${capitalize(cert.level)}</p>
      <div class="metric-row"><span>Country Value</span><span>${item.countryScore}/5</span></div>
      <div class="metric-row"><span>Role Relevance</span><span>${item.relevance}/5</span></div>
      <div class="metric-row"><span>Cost</span><span>$${cert.costUSD}</span></div>
      <div class="metric-row"><span>Effort</span><span>${cert.effortHoursMin}-${cert.effortHoursMax}h</span></div>
      <div class="tag-list">${tracks}</div>
    </article>
  `;
}

function renderCountryPath(country, certById) {
  const stages = [
    { key: "beginner", label: "Beginner Baseline" },
    { key: "intermediate", label: "Intermediate Build" },
    { key: "advanced", label: "Advanced Differentiator" },
  ];

  return stages
    .map((stage) => {
      const certIds = country.recommendedPaths[stage.key] || [];
      const certs = certIds.map((id) => certById[id]).filter(Boolean);
      const top = certs[0];

      if (!top) {
        return `<article class="path-card"><span class="stage-badge">${stage.label}</span><h4>No mapped certifications</h4><p>Update country dataset.</p></article>`;
      }

      return `
        <article class="path-card">
          <span class="stage-badge">${stage.label}</span>
          <h4>${escapeHtml(top.name)}</h4>
          <p>${escapeHtml(top.vendor)} | ${top.effortHoursMin}-${top.effortHoursMax}h | $${top.costUSD}</p>
          <div class="tag-list">${certs
            .slice(1)
            .map((cert) => `<span class="tag">${escapeHtml(cert.name)}</span>`)
            .join("")}</div>
        </article>
      `;
    })
    .join("");
}

function renderDemandBars(domainDemand) {
  const entries = Object.entries(domainDemand || {}).sort((a, b) => b[1] - a[1]);
  return entries
    .map(([domain, score]) => {
      const pct = Math.max(10, Math.min(100, score * 20));
      return `
        <div class="trend-row">
          <div class="trend-head"><span>${escapeHtml(DOMAIN_LABELS[domain] || domain)}</span><span>${score}/5</span></div>
          <div class="trend-bar"><div class="trend-fill" style="width:${pct}%"></div></div>
        </div>
      `;
    })
    .join("");
}

function buildQuickRecommendations({ country, role, level, budget, top, ranked }) {
  const recs = [];
  const roleLabel = role?.label || "selected role";

  if (top) {
    recs.push(`Start with ${top.cert.name} as your highest fit for current market-role lens.`);
  }

  if (budget <= 200) {
    recs.push("With a constrained budget, prioritize low-cost, high-signal practical certs first.");
  } else if (budget >= 1000) {
    recs.push("Your budget allows one premium cert plus one practical cert for better conversion.");
  }

  if (level === "beginner") {
    recs.push("Avoid stacking advanced governance certs early; pair one foundational cert with one project deliverable.");
  }

  const topThree = ranked.slice(0, 3).map((item) => item.cert.name);
  if (topThree.length) {
    recs.push(`Current top stack: ${topThree.join(" -> ")}.`);
  }

  recs.push(country.marketNotes[0] || "Build project evidence for every certification cycle.");
  recs.push(`Role focus for ${roleLabel}: prioritize ${normalizeDomains(role?.focusDomains || []).map((d) => DOMAIN_LABELS[d] || d).join(", ")}.`);

  return recs.slice(0, 6);
}

function scoreCertification(cert, countryScore, relevance) {
  const costPenalty = Math.min(12, cert.costUSD / 200);
  return Math.round((countryScore * 34) + (relevance * 30) + (cert.roiBase * 22) + (cert.globalRecognition * 18) - costPenalty);
}

function toFivePointScale(rawScore) {
  const normalized = Math.round(rawScore / 104);
  return Math.max(1, Math.min(5, normalized));
}

function getCountryScore(data, certId, countryId) {
  const scoreRow = data.scoreByCert[certId];
  const explicit = scoreRow?.countryScores?.[countryId];
  if (Number.isFinite(explicit)) return explicit;

  const cert = data.certById[certId];
  if (!cert) return 1;

  // Fallback for future partial datasets: derive a conservative market score.
  const regionAffinity = Array.isArray(cert.bestForRegions) && cert.bestForRegions.includes(countryId) ? 1 : 0;
  const base = Math.round((cert.globalRecognition + cert.roiBase) / 2);
  return Math.max(1, Math.min(5, base + regionAffinity));
}

function getRoleRelevance(cert, role) {
  if (!role) return average(Object.values(cert.jobRelevance || { appsec: 3, cloudsec: 3, soc: 3, governance: 3, offensive: 3, mlsec: 3 }));

  const domains = normalizeDomains(role.focusDomains);
  const values = domains
    .map((domain) => cert.jobRelevance[domain])
    .filter((value) => Number.isFinite(value));

  if (!values.length) return 2;
  return Math.round(average(values));
}

function normalizeDomains(domains) {
  return unique((domains || []).map((domain) => DOMAIN_ALIAS[domain] || domain));
}

function isLevelMatch(certLevel, selectedLevel) {
  if (selectedLevel === "any") return true;

  const certRank = LEVEL_RANK[certLevel] || 2;
  const target = LEVEL_RANK[selectedLevel] || 3;

  if (selectedLevel === "beginner") return certRank <= 1;
  if (selectedLevel === "intermediate") return certRank <= 2;
  return certRank <= target;
}

function renderScorePill(score) {
  const cls = score >= 4 ? "high" : score >= 3 ? "med" : "low";
  return `<span class="score-pill ${cls}">${score}/5</span>`;
}

function capitalize(text) {
  return String(text || "").charAt(0).toUpperCase() + String(text || "").slice(1);
}

function average(numbers) {
  if (!numbers.length) return 0;
  return numbers.reduce((sum, n) => sum + n, 0) / numbers.length;
}

function unique(items) {
  return [...new Set(items)];
}

function indexBy(items, key) {
  return (items || []).reduce((acc, item) => {
    acc[item[key]] = item;
    return acc;
  }, {});
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
