const STORAGE_KEY = "cyberStudyOS.v1";

const DOMAIN_META = {
  fundamentals: { label: "Fundamentals", color: "#22c55e" },
  appsec: { label: "AppSec", color: "#f59e0b" },
  cloudsec: { label: "CloudSec", color: "#00ff41" },
  soc: { label: "SOC", color: "#06b6d4" },
  mlsec: { label: "ML Security", color: "#10b981" },
  offensive: { label: "Offensive", color: "#ef4444" },
};

const TRACK_THEME = {
  appsec: "Secure by design and exploit resilience",
  cloudsec: "Identity-first cloud defense and IaC hygiene",
  soc: "Detection engineering and incident workflow depth",
  mlsec: "AI threat modeling and adversarial robustness",
  offensive: "Offensive validation for defensive strength",
};

const TRACK_LIBRARY = {
  fundamentals: [
    "TCP/IP, DNS, and HTTP attack surfaces",
    "Linux hardening and process observability",
    "Authentication and authorization patterns",
    "Threat modeling with STRIDE",
  ],
  appsec: [
    "OWASP Top 10 and API Top 10 exploit chains",
    "SAST and DAST triage workflow",
    "AuthN and session hardening",
    "Secure code review cadence",
  ],
  cloudsec: [
    "IAM least privilege policy design",
    "Cloud logging and threat detection baselines",
    "Container and runtime hardening",
    "Infrastructure-as-code guardrails",
  ],
  soc: [
    "Detection rule design with high signal quality",
    "Incident triage and hypothesis generation",
    "SIEM tuning and false positive management",
    "Threat hunting with MITRE ATT&CK mapping",
  ],
  mlsec: [
    "Prompt injection and LLM defense patterns",
    "Model poisoning and adversarial example testing",
    "ML pipeline supply-chain controls",
    "AI red team simulation and guardrail validation",
  ],
  offensive: [
    "Recon to exploit path prioritization",
    "Web and API exploit development",
    "Privilege escalation and lateral movement labs",
    "Post-exploitation reporting discipline",
  ],
};

const ACTIVITY_MULTIPLIER = {
  reading: 1,
  lab: 1.45,
  build: 1.8,
  writeup: 1.25,
  review: 0.85,
};

const DIFFICULTY_MULTIPLIER = {
  low: 0.9,
  medium: 1,
  high: 1.25,
};

const state = loadState();

const profileForm = document.getElementById("profileForm");
const planTimeline = document.getElementById("planTimeline");
const sessionForm = document.getElementById("sessionForm");
const sessionTableBody = document.getElementById("sessionTableBody");
const recommendationsList = document.getElementById("recommendationsList");
const executionQueue = document.getElementById("executionQueue");
const weeklyMinutesChart = document.getElementById("weeklyMinutesChart");
const domainDonut = document.getElementById("domainDonut");
const domainLegend = document.getElementById("domainLegend");

const kpiHours = document.getElementById("kpiHours");
const kpiTotalXp = document.getElementById("kpiTotalXp");
const kpiStreak = document.getElementById("kpiStreak");
const kpiWeeklyProgress = document.getElementById("kpiWeeklyProgress");
const kpiPlanCompletion = document.getElementById("kpiPlanCompletion");
const kpiAlignment = document.getElementById("kpiAlignment");

const tracker7dMinutes = document.getElementById("tracker7dMinutes");
const tracker7dXp = document.getElementById("tracker7dXp");
const trackerAvgSession = document.getElementById("trackerAvgSession");
const trackerDeepRatio = document.getElementById("trackerDeepRatio");

const filterDomain = document.getElementById("filterDomain");
const filterActivity = document.getElementById("filterActivity");
const filterWindow = document.getElementById("filterWindow");
const filterSort = document.getElementById("filterSort");

document.getElementById("exportDataBtn").addEventListener("click", exportData);
document.getElementById("importDataInput").addEventListener("change", importData);
document.getElementById("resetDataBtn").addEventListener("click", resetData);

profileForm.addEventListener("submit", onProfileSubmit);
sessionForm.addEventListener("submit", onSessionSubmit);

init();

function init() {
  sessionForm.date.value = dateToISO(new Date());
  hydrateProfileForm();
  hydrateTrackerFilters();

  [filterDomain, filterActivity, filterWindow, filterSort].forEach((el) => {
    if (el) el.addEventListener("change", onTrackerFilterChange);
  });

  renderAll();
}

function loadState() {
  const fallback = {
    profile: {
      name: "",
      targetRole: "",
      level: "intermediate",
      hoursPerWeek: 12,
      targetDate: "",
      priorityTrack: "mlsec",
      domains: ["fundamentals", "appsec", "cloudsec", "soc", "mlsec"],
    },
    plan: [],
    sessions: [],
    trackerFilters: {
      domain: "all",
      activityType: "all",
      windowDays: 7,
      sortBy: "newest",
    },
    createdAt: new Date().toISOString(),
  };

  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw);
    return {
      ...fallback,
      ...parsed,
      profile: { ...fallback.profile, ...(parsed.profile || {}) },
      plan: Array.isArray(parsed.plan) ? parsed.plan : [],
      sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      trackerFilters: { ...fallback.trackerFilters, ...(parsed.trackerFilters || {}) },
    };
  } catch {
    return fallback;
  }
}

function saveState() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function hydrateProfileForm() {
  const p = state.profile;
  profileForm.name.value = p.name || "";
  profileForm.targetRole.value = p.targetRole || "";
  profileForm.level.value = p.level || "intermediate";
  profileForm.hoursPerWeek.value = p.hoursPerWeek || 12;
  profileForm.targetDate.value = p.targetDate || "";
  profileForm.priorityTrack.value = p.priorityTrack || "mlsec";

  const checks = profileForm.querySelectorAll('input[name="domains"]');
  checks.forEach((cb) => {
    cb.checked = (p.domains || []).includes(cb.value);
  });
}

function hydrateTrackerFilters() {
  if (!filterDomain || !filterActivity || !filterWindow || !filterSort) return;
  const f = state.trackerFilters || {};
  filterDomain.value = f.domain || "all";
  filterActivity.value = f.activityType || "all";
  filterWindow.value = String(f.windowDays || 7);
  filterSort.value = f.sortBy || "newest";
}

function onTrackerFilterChange() {
  if (!filterDomain || !filterActivity || !filterWindow || !filterSort) return;
  state.trackerFilters = {
    domain: filterDomain.value,
    activityType: filterActivity.value,
    windowDays: filterWindow.value === "all" ? "all" : Number(filterWindow.value),
    sortBy: filterSort.value,
  };
  saveState();
  renderSessions();
}

function onProfileSubmit(event) {
  event.preventDefault();
  const data = new FormData(profileForm);
  const domains = data.getAll("domains");
  if (domains.length === 0) {
    alert("Select at least one focus domain.");
    return;
  }

  state.profile = {
    name: String(data.get("name") || "").trim(),
    targetRole: String(data.get("targetRole") || "").trim(),
    level: String(data.get("level") || "intermediate"),
    hoursPerWeek: Number(data.get("hoursPerWeek") || 12),
    targetDate: String(data.get("targetDate") || ""),
    priorityTrack: String(data.get("priorityTrack") || "mlsec"),
    domains,
  };

  state.plan = generatePlan(state.profile, 12);
  saveState();
  renderAll();
}

function generatePlan(profile, weeksCount) {
  const selected = profile.domains.length ? [...profile.domains] : ["fundamentals"];
  const priority = profile.priorityTrack;
  const queue = [priority, ...selected.filter((d) => d !== priority)];

  const weekStart = startOfWeek(new Date());
  const plan = [];

  for (let week = 1; week <= weeksCount; week += 1) {
    const startDate = addDays(weekStart, (week - 1) * 7);
    const domain = pickDomainForWeek(week, queue);
    const theme = pickTheme(week, domain, priority);
    const content = pickContent(domain, week);
    const intensity = profile.level === "beginner" ? "steady" : profile.level === "advanced" ? "aggressive" : "balanced";

    plan.push({
      id: `week-${week}`,
      week,
      domain,
      startDate: dateToISO(startDate),
      theme,
      objectives: [
        `Target role alignment: ${profile.targetRole || "Cybersecurity role"}`,
        `Primary focus: ${DOMAIN_META[domain].label}`,
        `Study intensity: ${intensity} (${profile.hoursPerWeek}h/week)`,
      ],
      labs: [
        `${content[0]} lab with notes`,
        `${content[1]} implementation or walkthrough`,
        `One writeup from ${DOMAIN_META[domain].label} perspective`,
      ],
      deliverable: week >= 10
        ? "Portfolio artifact, impact notes, and interview story"
        : `${DOMAIN_META[domain].label} mini artifact with reproducible steps`,
      estimatedHours: profile.hoursPerWeek,
      completed: false,
    });
  }

  return plan;
}

function pickDomainForWeek(week, queue) {
  if (week === 1 || week === 2) return "fundamentals";
  if (week >= 10) return queue[0] || "fundamentals";
  const idx = (week - 3) % queue.length;
  return queue[idx] || "fundamentals";
}

function pickTheme(week, domain, priority) {
  if (week === 1) return "System setup, baselining, and study calibration";
  if (week === 2) return "Core fundamentals and command fluency";
  if (week === 10) return `Capstone design using ${DOMAIN_META[priority]?.label || "priority track"}`;
  if (week === 11) return "Capstone build and evidence collection";
  if (week === 12) return "Portfolio packaging and interview readiness";
  return TRACK_THEME[domain] || "Security engineering progression";
}

function pickContent(domain, week) {
  const options = TRACK_LIBRARY[domain] || TRACK_LIBRARY.fundamentals;
  const a = options[(week - 1) % options.length];
  const b = options[(week + 1) % options.length];
  return [a, b];
}

function renderAll() {
  renderPlan();
  renderSessions();
  renderKpis();
  renderRecommendations();
  renderAnalytics();
}

function renderPlan() {
  if (!state.plan.length) {
    planTimeline.innerHTML = '<p class="mono">Generate a profile to create your 12-week plan.</p>';
    return;
  }

  planTimeline.innerHTML = state.plan
    .map((week) => {
      const objectives = week.objectives.map((o) => `<li>${escapeHtml(o)}</li>`).join("");
      const labs = week.labs.map((l) => `<li>${escapeHtml(l)}</li>`).join("");

      return `
        <article class="week-card" data-week-id="${week.id}">
          <div class="week-head">
            <h4>Week ${week.week}: ${escapeHtml(week.theme)}</h4>
            <span class="badge">${escapeHtml(DOMAIN_META[week.domain].label)}</span>
          </div>
          <p class="mono">Starts ${week.startDate} | ${week.estimatedHours}h target</p>
          <p><strong>Objectives</strong></p>
          <ul class="objective-list">${objectives}</ul>
          <p><strong>Labs</strong></p>
          <ul class="lab-list">${labs}</ul>
          <p><strong>Deliverable:</strong> ${escapeHtml(week.deliverable)}</p>
          <label class="mono"><input type="checkbox" data-plan-toggle="${week.id}" ${week.completed ? "checked" : ""} /> mark week complete</label>
        </article>
      `;
    })
    .join("");

  const toggles = planTimeline.querySelectorAll("[data-plan-toggle]");
  toggles.forEach((el) => {
    el.addEventListener("change", (e) => {
      const id = e.target.getAttribute("data-plan-toggle");
      const found = state.plan.find((item) => item.id === id);
      if (!found) return;
      found.completed = e.target.checked;
      saveState();
      renderKpis();
      renderRecommendations();
    });
  });
}

function onSessionSubmit(event) {
  event.preventDefault();
  const data = new FormData(sessionForm);

  const minutes = Number(data.get("minutes") || 0);
  if (minutes <= 0) {
    alert("Minutes must be greater than 0.");
    return;
  }

  const activityType = String(data.get("activityType"));
  const difficulty = String(data.get("difficulty"));
  const xp = computeXP(minutes, activityType, difficulty);

  const session = {
    id: `s_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    date: String(data.get("date")),
    minutes,
    domain: String(data.get("domain")),
    activityType,
    difficulty,
    note: String(data.get("note") || "").trim(),
    xp,
  };

  state.sessions.unshift(session);
  state.sessions.sort((a, b) => (a.date > b.date ? -1 : 1));
  saveState();

  sessionForm.reset();
  sessionForm.date.value = dateToISO(new Date());
  sessionForm.minutes.value = "45";
  sessionForm.activityType.value = "lab";
  sessionForm.difficulty.value = "medium";

  renderAll();
}

function computeXP(minutes, activityType, difficulty) {
  const base = Math.max(1, minutes / 10);
  const activity = ACTIVITY_MULTIPLIER[activityType] || 1;
  const diff = DIFFICULTY_MULTIPLIER[difficulty] || 1;
  return Math.max(5, Math.round(base * activity * diff));
}

function renderSessions() {
  const filtered = getFilteredSessions(state.sessions, state.trackerFilters);
  renderTrackerSummary(filtered, state.sessions);

  if (!filtered.length) {
    sessionTableBody.innerHTML = '<tr><td colspan="8" class="mono">No sessions match current filters yet.</td></tr>';
    return;
  }

  sessionTableBody.innerHTML = filtered
    .slice(0, 120)
    .map(
      (s) => `
      <tr>
        <td>${escapeHtml(s.date)}</td>
        <td>${escapeHtml(DOMAIN_META[s.domain]?.label || s.domain)}</td>
        <td>${escapeHtml(s.activityType)}</td>
        <td>${escapeHtml(s.difficulty)}</td>
        <td>${s.minutes}</td>
        <td>${s.xp}</td>
        <td>${escapeHtml(s.note ? truncate(s.note, 64) : "-")}</td>
        <td><button data-delete-session="${s.id}">Delete</button></td>
      </tr>
    `
    )
    .join("");

  const buttons = sessionTableBody.querySelectorAll("[data-delete-session]");
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-delete-session");
      state.sessions = state.sessions.filter((s) => s.id !== id);
      saveState();
      renderAll();
    });
  });
}

function renderTrackerSummary(filteredSessions, allSessions) {
  if (!tracker7dMinutes || !tracker7dXp || !trackerAvgSession || !trackerDeepRatio) return;

  const sessions7d = getSessionsInDays(allSessions, 7);
  const minutes7d = sessions7d.reduce((sum, s) => sum + s.minutes, 0);
  const xp7d = sessions7d.reduce((sum, s) => sum + s.xp, 0);

  const avgMinutes = filteredSessions.length
    ? Math.round(filteredSessions.reduce((sum, s) => sum + s.minutes, 0) / filteredSessions.length)
    : 0;

  const deepWorkSessions = filteredSessions.filter((s) => s.minutes >= 60 || (s.activityType === "lab" && s.difficulty === "high"));
  const deepRatio = filteredSessions.length ? Math.round((deepWorkSessions.length / filteredSessions.length) * 100) : 0;

  tracker7dMinutes.textContent = `${minutes7d}m`;
  tracker7dXp.textContent = `${xp7d}`;
  trackerAvgSession.textContent = `${avgMinutes}m`;
  trackerDeepRatio.textContent = `${deepRatio}%`;
}

function renderKpis() {
  if (!kpiHours || !kpiTotalXp || !kpiStreak || !kpiWeeklyProgress || !kpiPlanCompletion || !kpiAlignment) return;

  const totalMinutes = state.sessions.reduce((sum, s) => sum + s.minutes, 0);
  const totalHours = (totalMinutes / 60).toFixed(1);
  const totalXp = state.sessions.reduce((sum, s) => sum + s.xp, 0);

  const streak = computeStreak(state.sessions);
  const weeklyMinutes = minutesThisWeek(state.sessions);
  const weeklyTarget = (state.profile.hoursPerWeek || 12) * 60;
  const weeklyProgress = weeklyTarget > 0 ? Math.min(100, Math.round((weeklyMinutes / weeklyTarget) * 100)) : 0;

  const completedWeeks = state.plan.filter((w) => w.completed).length;
  const planCompletion = state.plan.length ? Math.round((completedWeeks / state.plan.length) * 100) : 0;
  const alignment = computePlannerAlignment(state);

  kpiHours.textContent = `${totalHours}h`;
  kpiTotalXp.textContent = `${totalXp}`;
  kpiStreak.textContent = `${streak} days`;
  kpiWeeklyProgress.textContent = `${weeklyProgress}%`;
  kpiPlanCompletion.textContent = `${planCompletion}%`;
  kpiAlignment.textContent = `${alignment}%`;
}

function renderRecommendations() {
  if (!recommendationsList || !executionQueue) return;

  const result = buildRecommendations();
  const recommendations = result.recommendations;
  const execution = result.execution;

  recommendationsList.innerHTML = recommendations
    .map(
      (r) => `
      <article class="rec-card rec-${r.priority}">
        <div class="rec-head">
          <span class="rec-priority">${escapeHtml(r.priority.toUpperCase())}</span>
          <h4>${escapeHtml(r.title)}</h4>
        </div>
        <p><strong>Why:</strong> ${escapeHtml(r.why)}</p>
        <p><strong>Action:</strong> ${escapeHtml(r.action)}</p>
        <p class="mono">Metric: ${escapeHtml(r.metric)}</p>
      </article>
    `
    )
    .join("");

  executionQueue.innerHTML = execution.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

function buildRecommendations() {
  const items = [];

  if (!state.plan.length) {
    return {
      recommendations: [
        {
          priority: "high",
          title: "Initialize your planner baseline",
          why: "Recommendations are empty because no planner state exists yet.",
          action: "Set profile fields and generate a 12-week plan, then log your first study session.",
          metric: "Plan weeks: 0 | Sessions: 0",
        },
      ],
      execution: [
        "Create profile and select a priority track.",
        "Set weekly study target and generate the plan.",
        "Log first session with meaningful notes.",
      ],
    };
  }

  const analytics = buildSystemAnalytics(state);

  if (analytics.weeklyProgress < 55) {
    items.push({
      priority: "high",
      title: "Close weekly pacing gap",
      why: `You are at ${analytics.weeklyProgress}% of this week's target (${analytics.weeklyMinutes}/${analytics.weeklyTarget} minutes).`,
      action: `Add ${Math.ceil(analytics.weeklyGap / 60)} focused sessions before week end, prioritizing ${analytics.currentWeekDomainLabel}.`,
      metric: `Gap: ${analytics.weeklyGap}m`,
    });
  } else if (analytics.weeklyProgress >= 100) {
    items.push({
      priority: "low",
      title: "Use surplus time strategically",
      why: `Weekly goal is complete at ${analytics.weeklyProgress}% and you are ahead of pace.`,
      action: "Invest extra time into one portfolio-grade artifact linked to current planner week.",
      metric: `Surplus: ${analytics.weeklyMinutes - analytics.weeklyTarget}m`,
    });
  }

  if (analytics.planPaceDelta < 0) {
    items.push({
      priority: "high",
      title: "Recover planner schedule drift",
      why: `Planner pace is behind by ${Math.abs(analytics.planPaceDelta)} week(s) against calendar progress.`,
      action: "Close one pending week with a minimum deliverable, then mark completion only after evidence is produced.",
      metric: `Completed weeks: ${analytics.completedWeeks}/${analytics.expectedWeek}`,
    });
  }

  if (analytics.streak === 0) {
    items.push({
      priority: "high",
      title: "Rebuild study consistency",
      why: "Current streak is broken, which increases restart friction and plan slippage risk.",
      action: "Run one 20-minute micro-session today and one 45-minute lab tomorrow to restart momentum.",
      metric: `Streak: ${analytics.streak} days`,
    });
  } else if (analytics.streak >= 14) {
    items.push({
      priority: "low",
      title: "Capitalize on strong streak",
      why: `You have a ${analytics.streak}-day streak and can safely increase challenge complexity.`,
      action: "Add one high-difficulty lab and convert findings into a structured writeup this week.",
      metric: `High-difficulty sessions this week: ${analytics.highDifficulty7d}`,
    });
  }

  if (analytics.labRatio < 35) {
    items.push({
      priority: "high",
      title: "Increase hands-on depth",
      why: `Only ${analytics.labRatio}% of your tracked minutes are lab-oriented, which limits interview readiness.`,
      action: "Rebalance to at least 40% lab time over next 7 days using practical tasks from the current planner week.",
      metric: `Lab ratio: ${analytics.labRatio}%`,
    });
  }

  if (analytics.writeupCount7d < 1) {
    items.push({
      priority: "medium",
      title: "Improve evidence trail",
      why: "No writeup sessions were logged in the last 7 days, reducing portfolio visibility.",
      action: "Schedule one 45-minute writeup session for the strongest lab from this week.",
      metric: `Writeups (7d): ${analytics.writeupCount7d}`,
    });
  }

  if (analytics.weakDomain && analytics.weakDomainMinutes < 120) {
    items.push({
      priority: "medium",
      title: `Repair domain coverage gap in ${analytics.weakDomainLabel}`,
      why: `${analytics.weakDomainLabel} has only ${analytics.weakDomainMinutes} minutes logged in the active analysis window.`,
      action: `Insert at least two focused sessions in ${analytics.weakDomainLabel} to maintain breadth and planner coherence.`,
      metric: `Coverage window: ${analytics.coverageWindowDays}d`,
    });
  }

  if (analytics.burnoutRisk === "elevated") {
    items.push({
      priority: "medium",
      title: "Reduce burnout probability",
      why: "Intensity is high with limited low-friction recovery sessions in recent days.",
      action: "Keep one light review block and one medium lab block instead of back-to-back high-intensity sessions.",
      metric: `High-intensity ratio (14d): ${analytics.highIntensityRatio}%`,
    });
  }

  if (analytics.plannerAlignment < 65) {
    items.push({
      priority: "high",
      title: "Improve planner-to-tracker alignment",
      why: `Current alignment score is ${analytics.plannerAlignment}% indicating execution drift from plan intent.`,
      action: `Prioritize sessions in ${analytics.currentWeekDomainLabel} and complete the week deliverable before switching contexts.`,
      metric: `Alignment score: ${analytics.plannerAlignment}%`,
    });
  }

  if (!items.length) {
    items.push({
      priority: "low",
      title: "Sustain and compound progress",
      why: "Your pacing, distribution, and planner adherence are currently healthy.",
      action: "Use this week to create one standout portfolio case study with measurable impact and lessons learned.",
      metric: `Alignment score: ${analytics.plannerAlignment}%`,
    });
  }

  const sorted = items.sort((a, b) => priorityRank(a.priority) - priorityRank(b.priority)).slice(0, 8);
  const execution = buildExecutionQueue(analytics, sorted);

  return { recommendations: sorted, execution };
}

function buildSystemAnalytics(appState) {
  const sessions = appState.sessions;
  const profile = appState.profile;
  const weeklyTarget = (profile.hoursPerWeek || 12) * 60;
  const weeklyMinutes = minutesThisWeek(sessions);
  const weeklyProgress = weeklyTarget > 0 ? Math.round((weeklyMinutes / weeklyTarget) * 100) : 0;
  const weeklyGap = Math.max(0, weeklyTarget - weeklyMinutes);

  const completedWeeks = appState.plan.filter((w) => w.completed).length;
  const expectedWeek = Math.min(appState.plan.length, Math.max(1, weeksSincePlanStart(appState.plan)));
  const planPaceDelta = completedWeeks - expectedWeek;

  const currentWeekObj = appState.plan[Math.max(0, expectedWeek - 1)] || appState.plan[0];
  const currentWeekDomainLabel = DOMAIN_META[currentWeekObj?.domain]?.label || "current domain";

  const sessions7d = getSessionsInDays(sessions, 7);
  const sessions14d = getSessionsInDays(sessions, 14);
  const writeupCount7d = sessions7d.filter((s) => s.activityType === "writeup").length;
  const highDifficulty7d = sessions7d.filter((s) => s.difficulty === "high").length;

  const totalMinutes = sessions.reduce((sum, s) => sum + s.minutes, 0) || 1;
  const labMinutes = sessions.filter((s) => s.activityType === "lab").reduce((sum, s) => sum + s.minutes, 0);
  const labRatio = Math.round((labMinutes / totalMinutes) * 100);

  const highIntensityMinutes = sessions14d
    .filter((s) => s.difficulty === "high" || s.minutes >= 90)
    .reduce((sum, s) => sum + s.minutes, 0);
  const total14dMinutes = sessions14d.reduce((sum, s) => sum + s.minutes, 0) || 1;
  const highIntensityRatio = Math.round((highIntensityMinutes / total14dMinutes) * 100);

  const trackedDomains = profile.domains || [];
  const domainMinutesWindow = summarizeBy(getSessionsInDays(sessions, 21), "domain", (s) => s.minutes);
  const weakest = trackedDomains
    .map((d) => ({ domain: d, minutes: domainMinutesWindow[d] || 0 }))
    .sort((a, b) => a.minutes - b.minutes)[0];

  const plannerAlignment = computePlannerAlignment(appState);

  return {
    weeklyTarget,
    weeklyMinutes,
    weeklyProgress,
    weeklyGap,
    completedWeeks,
    expectedWeek,
    planPaceDelta,
    streak: computeStreak(sessions),
    writeupCount7d,
    highDifficulty7d,
    currentWeekDomainLabel,
    labRatio,
    highIntensityRatio,
    burnoutRisk: highIntensityRatio > 65 ? "elevated" : "normal",
    weakDomain: weakest?.domain,
    weakDomainLabel: DOMAIN_META[weakest?.domain]?.label || "",
    weakDomainMinutes: weakest?.minutes || 0,
    coverageWindowDays: 21,
    plannerAlignment,
  };
}

function buildExecutionQueue(analytics, recommendations) {
  const queue = [];

  if (analytics.weeklyGap > 0) {
    queue.push(`Day 1: ${Math.min(90, analytics.weeklyGap)} minutes in ${analytics.currentWeekDomainLabel} with one lab-first session.`);
  }

  queue.push("Day 2: 45-minute focused practice and 15-minute reflection note to capture learnings.");

  if (analytics.writeupCount7d < 1) {
    queue.push("Day 3: 45-minute writeup block; publish a concise artifact summary.");
  } else {
    queue.push("Day 3: Deepen one existing artifact by adding threat model and remediation clarity.");
  }

  if (analytics.weakDomainLabel) {
    queue.push(`Day 4: 60-minute targeted session in ${analytics.weakDomainLabel} to close domain coverage gap.`);
  }

  queue.push("Day 5: High-difficulty lab (60-90m) mapped to current planner objectives.");
  queue.push("Day 6: 30-minute review and KPI check against weekly target and planner alignment.");
  queue.push("Day 7: Finalize one concrete deliverable and mark week complete only after evidence is saved.");

  if (recommendations.some((r) => r.priority === "high")) {
    queue.unshift("Immediate: Execute the highest-priority recommendation before starting new optional tasks.");
  }

  return queue.slice(0, 8);
}

function priorityRank(priority) {
  if (priority === "high") return 0;
  if (priority === "medium") return 1;
  return 2;
}

function computePlannerAlignment(appState) {
  if (!appState.plan.length) return 0;

  const weeklyTarget = (appState.profile.hoursPerWeek || 12) * 60;
  const weeklyMinutes = minutesThisWeek(appState.sessions);
  const paceScore = weeklyTarget > 0 ? Math.min(100, Math.round((weeklyMinutes / weeklyTarget) * 100)) : 0;

  const completedWeeks = appState.plan.filter((w) => w.completed).length;
  const expectedWeek = Math.min(appState.plan.length, Math.max(1, weeksSincePlanStart(appState.plan)));
  const planScore = Math.max(0, 100 - Math.max(0, (expectedWeek - completedWeeks) * 20));

  const currentWeek = appState.plan[Math.max(0, expectedWeek - 1)] || appState.plan[0];
  const sessions7d = getSessionsInDays(appState.sessions, 7);
  const weekDomainMinutes = sessions7d
    .filter((s) => s.domain === currentWeek?.domain)
    .reduce((sum, s) => sum + s.minutes, 0);
  const domainScore = weeklyMinutes > 0 ? Math.min(100, Math.round((weekDomainMinutes / weeklyMinutes) * 100 * 1.5)) : 0;

  const qualityScore = Math.min(100, Math.round((paceScore * 0.45) + (planScore * 0.35) + (domainScore * 0.2)));
  return qualityScore;
}

function getFilteredSessions(sessions, filters) {
  let result = [...sessions];

  if (filters.domain && filters.domain !== "all") {
    result = result.filter((s) => s.domain === filters.domain);
  }

  if (filters.activityType && filters.activityType !== "all") {
    result = result.filter((s) => s.activityType === filters.activityType);
  }

  if (filters.windowDays !== "all") {
    const windowDays = Number(filters.windowDays || 7);
    const start = addDays(startOfDay(new Date()), -windowDays + 1);
    result = result.filter((s) => new Date(`${s.date}T00:00:00`) >= start);
  }

  if (filters.sortBy === "xp") {
    result.sort((a, b) => b.xp - a.xp || (a.date > b.date ? -1 : 1));
  } else if (filters.sortBy === "minutes") {
    result.sort((a, b) => b.minutes - a.minutes || (a.date > b.date ? -1 : 1));
  } else {
    result.sort((a, b) => (a.date > b.date ? -1 : 1));
  }

  return result;
}

function getSessionsInDays(sessions, days) {
  const start = addDays(startOfDay(new Date()), -days + 1);
  return sessions.filter((s) => new Date(`${s.date}T00:00:00`) >= start);
}

function truncate(text, maxLen) {
  if (!text) return "";
  return text.length <= maxLen ? text : `${text.slice(0, maxLen - 3)}...`;
}

function renderAnalytics() {
  drawWeeklyMinutesChart();
  drawDomainDonut();
}

function drawWeeklyMinutesChart() {
  const canvas = weeklyMinutesChart;
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;

  ctx.clearRect(0, 0, width, height);

  const weeks = getLastNWeekBuckets(state.sessions, 8);
  const max = Math.max(60, ...weeks.map((w) => w.minutes));

  ctx.fillStyle = "rgba(255,255,255,0.08)";
  for (let i = 0; i <= 4; i += 1) {
    const y = 20 + (i * (height - 50)) / 4;
    ctx.fillRect(30, y, width - 45, 1);
  }

  const barGap = 12;
  const barArea = width - 60;
  const barWidth = (barArea - barGap * (weeks.length - 1)) / weeks.length;

  weeks.forEach((w, i) => {
    const x = 32 + i * (barWidth + barGap);
    const h = ((height - 60) * w.minutes) / max;
    const y = height - 28 - h;

    const grad = ctx.createLinearGradient(0, y, 0, height);
    grad.addColorStop(0, "#00ff41");
    grad.addColorStop(1, "#10b981");
    ctx.fillStyle = grad;
    roundRect(ctx, x, y, barWidth, h, 6, true, false);

    ctx.fillStyle = "#9aa4b2";
    ctx.font = "11px JetBrains Mono";
    ctx.fillText(w.label, x, height - 10);
  });

  ctx.fillStyle = "#9aa4b2";
  ctx.font = "12px JetBrains Mono";
  ctx.fillText("Minutes", 4, 14);
}

function drawDomainDonut() {
  const totals = summarizeBy(state.sessions, "domain", (s) => s.minutes);
  const entries = Object.entries(DOMAIN_META).map(([key, meta]) => ({
    key,
    label: meta.label,
    color: meta.color,
    minutes: totals[key] || 0,
  }));

  const grand = entries.reduce((sum, e) => sum + e.minutes, 0);

  if (grand <= 0) {
    domainDonut.style.background = "radial-gradient(circle, rgba(255,255,255,0.04), rgba(255,255,255,0.02))";
    domainLegend.innerHTML = "<li>No domain data yet. Log sessions to view distribution.</li>";
    return;
  }

  let cursor = 0;
  const stops = [];

  entries.forEach((entry) => {
    const pct = (entry.minutes / grand) * 100;
    if (pct <= 0) return;
    const from = cursor;
    const to = cursor + pct;
    stops.push(`${entry.color} ${from.toFixed(2)}% ${to.toFixed(2)}%`);
    cursor = to;
  });

  domainDonut.style.background = `conic-gradient(${stops.join(", ")})`;

  domainLegend.innerHTML = entries
    .filter((e) => e.minutes > 0)
    .sort((a, b) => b.minutes - a.minutes)
    .map((entry) => {
      const pct = Math.round((entry.minutes / grand) * 100);
      return `<li><span class="left"><span class="swatch" style="background:${entry.color}"></span>${entry.label}</span><span>${pct}%</span></li>`;
    })
    .join("");
}

function exportData() {
  const payload = {
    exportedAt: new Date().toISOString(),
    version: 1,
    data: state,
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `cyber-study-os-export-${dateToISO(new Date())}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function importData(event) {
  const file = event.target.files?.[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = () => {
    try {
      const parsed = JSON.parse(String(reader.result));
      const imported = parsed.data || parsed;

      if (!imported || typeof imported !== "object") {
        throw new Error("Invalid import file");
      }

      state.profile = { ...state.profile, ...(imported.profile || {}) };
      state.plan = Array.isArray(imported.plan) ? imported.plan : [];
      state.sessions = Array.isArray(imported.sessions) ? imported.sessions : [];
      state.trackerFilters = { ...state.trackerFilters, ...(imported.trackerFilters || {}) };

      saveState();
      hydrateProfileForm();
      hydrateTrackerFilters();
      renderAll();
      alert("Import completed.");
    } catch {
      alert("Import failed. Please use a valid export JSON file.");
    } finally {
      event.target.value = "";
    }
  };

  reader.readAsText(file);
}

function resetData() {
  const ok = window.confirm("This will remove all Study OS data from this browser. Continue?");
  if (!ok) return;

  localStorage.removeItem(STORAGE_KEY);
  window.location.reload();
}

function computeStreak(sessions) {
  if (!sessions.length) return 0;

  const uniqueDays = new Set(sessions.map((s) => s.date));
  let streak = 0;
  let cursor = startOfDay(new Date());

  while (true) {
    const dayIso = dateToISO(cursor);
    if (uniqueDays.has(dayIso)) {
      streak += 1;
      cursor = addDays(cursor, -1);
      continue;
    }

    if (streak === 0) {
      cursor = addDays(cursor, -1);
      const yesterday = dateToISO(cursor);
      if (uniqueDays.has(yesterday)) {
        streak += 1;
        cursor = addDays(cursor, -1);
        continue;
      }
    }
    break;
  }

  return streak;
}

function minutesThisWeek(sessions) {
  const start = startOfWeek(new Date());
  const end = addDays(start, 7);
  return sessions
    .filter((s) => {
      const d = new Date(`${s.date}T00:00:00`);
      return d >= start && d < end;
    })
    .reduce((sum, s) => sum + s.minutes, 0);
}

function summarizeBy(arr, key, valueGetter) {
  return arr.reduce((acc, item) => {
    const k = item[key];
    acc[k] = (acc[k] || 0) + valueGetter(item);
    return acc;
  }, {});
}

function getLastNWeekBuckets(sessions, n) {
  const nowStart = startOfWeek(new Date());
  const buckets = [];

  for (let i = n - 1; i >= 0; i -= 1) {
    const weekStart = addDays(nowStart, -7 * i);
    const weekEnd = addDays(weekStart, 7);
    const label = `${weekStart.getMonth() + 1}/${weekStart.getDate()}`;

    const minutes = sessions
      .filter((s) => {
        const d = new Date(`${s.date}T00:00:00`);
        return d >= weekStart && d < weekEnd;
      })
      .reduce((sum, s) => sum + s.minutes, 0);

    buckets.push({
      label,
      minutes,
    });
  }

  return buckets;
}

function weeksSincePlanStart(plan) {
  if (!plan.length) return 1;
  const first = new Date(`${plan[0].startDate}T00:00:00`);
  const diff = Date.now() - first.getTime();
  return Math.floor(diff / (1000 * 60 * 60 * 24 * 7)) + 1;
}

function startOfWeek(date) {
  const d = startOfDay(date);
  const day = d.getDay();
  const mondayOffset = (day + 6) % 7;
  return addDays(d, -mondayOffset);
}

function startOfDay(date) {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate());
}

function addDays(date, days) {
  const d = new Date(date);
  d.setDate(d.getDate() + days);
  return d;
}

function dateToISO(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function roundRect(ctx, x, y, width, height, radius, fill, stroke) {
  const r = Math.min(radius, width / 2, height / 2);
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + width, y, x + width, y + height, r);
  ctx.arcTo(x + width, y + height, x, y + height, r);
  ctx.arcTo(x, y + height, x, y, r);
  ctx.arcTo(x, y, x + width, y, r);
  ctx.closePath();
  if (fill) ctx.fill();
  if (stroke) ctx.stroke();
}
