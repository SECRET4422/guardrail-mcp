(function () {
  const progress = document.getElementById("progress");
  const nav = document.querySelector(".nav");
  const menuBtn = document.getElementById("menuBtn");
  const navLinks = document.getElementById("navLinks");
  const navCta = document.getElementById("navCta");
  const toast = document.getElementById("toast");
  const year = document.getElementById("year");

  if (year) year.textContent = String(new Date().getFullYear());

  function showToast(msg) {
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 1700);
  }

  // Scroll progress + nav shadow
  function onScroll() {
    const h = document.documentElement;
    const max = h.scrollHeight - h.clientHeight;
    const p = max > 0 ? (h.scrollTop / max) * 100 : 0;
    if (progress) progress.style.width = p + "%";
    if (nav) nav.classList.toggle("scrolled", window.scrollY > 8);
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  // Mobile menu
  if (menuBtn) {
    menuBtn.addEventListener("click", () => {
      navLinks.classList.toggle("open");
      navCta.classList.toggle("open");
    });
    document.querySelectorAll("#navLinks a").forEach((a) => {
      a.addEventListener("click", () => {
        navLinks.classList.remove("open");
        navCta.classList.remove("open");
      });
    });
  }

  // Active section link
  const sections = [...document.querySelectorAll("section[id]")];
  const linkMap = {};
  document.querySelectorAll('.nav-links a[href^="#"]').forEach((a) => {
    linkMap[a.getAttribute("href").slice(1)] = a;
  });
  const ioNav = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (!e.isIntersecting) return;
        Object.values(linkMap).forEach((a) => a.classList.remove("active"));
        const a = linkMap[e.target.id];
        if (a) a.classList.add("active");
      });
    },
    { rootMargin: "-40% 0px -50% 0px", threshold: 0.01 }
  );
  sections.forEach((s) => ioNav.observe(s));

  // Reveal on scroll
  const reveals = document.querySelectorAll(".reveal");
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add("show");
          io.unobserve(e.target);
        }
      });
    },
    { threshold: 0.12 }
  );
  reveals.forEach((el) => io.observe(el));

  // Copy buttons
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const el = document.querySelector(btn.getAttribute("data-copy"));
      if (!el) return;
      const text = el.innerText || el.textContent;
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      }
      showToast("Copied to clipboard");
    });
  });

  // Animated counters when stats visible
  const stats = document.querySelectorAll("[data-count]");
  const ioStats = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (!e.isIntersecting) return;
        const el = e.target;
        const target = parseInt(el.getAttribute("data-count"), 10) || 0;
        const suffix = el.getAttribute("data-suffix") || "";
        const start = performance.now();
        const dur = 900;
        function tick(now) {
          const t = Math.min(1, (now - start) / dur);
          const val = Math.round(target * (0.2 + 0.8 * t));
          el.textContent = val + suffix;
          if (t < 1) requestAnimationFrame(tick);
          else el.textContent = target + suffix;
        }
        requestAnimationFrame(tick);
        ioStats.unobserve(el);
      });
    },
    { threshold: 0.5 }
  );
  stats.forEach((s) => ioStats.observe(s));


  // Live playground demo
  const runBtn = document.getElementById("runDemo");
  const demoInput = document.getElementById("demoInput");
  const findingsList = document.getElementById("findingsList");
  const findingsCount = document.getElementById("findingsCount");
  const scoreVal = document.getElementById("scoreVal");
  const scoreRing = document.getElementById("scoreRing");
  const verdictVal = document.getElementById("verdictVal");
  const enginesVal = document.getElementById("enginesVal");
  const issuesVal = document.getElementById("issuesVal");
  const policyVal = document.getElementById("policyVal");
  const riskVal = document.getElementById("riskVal");
  const gradeVal = document.getElementById("gradeVal");
  const sampleRow = document.getElementById("sampleRow");

  function loadSample(key) {
    if (!window.GuardRailDemo || !demoInput) return;
    const src = window.GuardRailDemo.SAMPLES[key];
    if (src != null) demoInput.value = src;
    if (sampleRow) {
      sampleRow.querySelectorAll(".sample-btn").forEach((b) => {
        b.classList.toggle("active", b.getAttribute("data-sample") === key);
      });
    }
  }

  function renderFindings(result) {
    if (!findingsList) return;
    const issues = result.issues || [];
    if (findingsCount) findingsCount.textContent = String(issues.length);
    if (!issues.length) {
      findingsList.innerHTML = '<div class="finding empty">No issues found. Try the “Python unsafe” sample.</div>';
      return;
    }
    findingsList.innerHTML = issues
      .map((i) => {
        const sev = i.severity || "INFO";
        return (
          '<article class="finding">' +
          '<div class="fh">' +
          `<span class="sev ${sev}">${sev}</span>` +
          `<span class="title">${escapeHtml(i.vulnerability_name || i.rule_id)}</span>` +
          "</div>" +
          `<div class="meta">${escapeHtml(i.rule_id)} · line ${i.line || "?"}</div>` +
          `<div class="ex">${escapeHtml(i.excerpt_redacted || "")}</div>` +
          `<div class="rem">${escapeHtml(i.remediation || "")}</div>` +
          "</article>"
        );
      })
      .join("");
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function applyResult(result) {
    const sec = (result.security_score && result.security_score.score) || 0;
    const grade = (result.security_score && result.security_score.grade) || "—";
    if (scoreVal) scoreVal.textContent = String(sec);
    if (scoreRing) scoreRing.style.setProperty("--p", sec + "%");
    if (verdictVal) {
      verdictVal.textContent = result.security_verdict || "—";
      verdictVal.className = result.security_verdict === "REJECTED" ? "v-bad" : "v-ok";
    }
    if (policyVal) {
      policyVal.textContent = result.policy_decision || "—";
      policyVal.className = result.policy_decision === "DENY" ? "v-bad" : "v-ok";
    }
    if (issuesVal) issuesVal.textContent = String(result.issue_count || 0);
    if (riskVal) riskVal.textContent = String(result.risk_score || 0);
    if (gradeVal) gradeVal.textContent = grade;
    if (enginesVal) enginesVal.textContent = (result.engines || []).join(" + ") || "—";
    renderFindings(result);
  }

  if (sampleRow) {
    sampleRow.addEventListener("click", (e) => {
      const btn = e.target.closest(".sample-btn");
      if (!btn) return;
      loadSample(btn.getAttribute("data-sample"));
    });
  }

  // default sample
  loadSample("python_bad");

  if (runBtn && demoInput && window.GuardRailDemo) {
    runBtn.addEventListener("click", () => {
      runBtn.disabled = true;
      runBtn.textContent = "Scanning…";
      // tiny async delay so UI paints and feels "live"
      setTimeout(() => {
        try {
          const result = window.GuardRailDemo.scan(demoInput.value);
          applyResult(result);
          showToast(
            result.security_verdict === "REJECTED"
              ? "Blocked: " + result.issue_count + " issue(s)"
              : "Approved: clean enough"
          );
        } catch (err) {
          showToast("Demo error: " + (err && err.message ? err.message : err));
          console.error(err);
        }
        runBtn.disabled = false;
        runBtn.textContent = "▶ Run scan";
      }, 180);
    });
  } else if (runBtn) {
    runBtn.addEventListener("click", () => showToast("Demo engine failed to load"));
  }


})();
