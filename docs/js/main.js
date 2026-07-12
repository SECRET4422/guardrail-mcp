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

  // Live demo
  const runBtn = document.getElementById("runDemo");
  const demoOut = document.getElementById("demoOut");
  const scoreVal = document.getElementById("scoreVal");
  const scoreRing = document.getElementById("scoreRing");
  const verdictVal = document.getElementById("verdictVal");
  const enginesVal = document.getElementById("enginesVal");
  const issuesVal = document.getElementById("issuesVal");
  const policyVal = document.getElementById("policyVal");

  if (runBtn && demoOut) {
    runBtn.addEventListener("click", () => {
      runBtn.disabled = true;
      runBtn.textContent = "Scanning…";
      demoOut.textContent =
        "→ hybrid_scan(source, language='python')\n→ engines: regex · ast · taint · treesitter · plugins\n\n";
      const lines = [
        { t: 280, s: "• GR-SEC-002   HIGH      Hardcoded credential  excerpt=password=\"Su****99\"" },
        { t: 620, s: "• GR-TAINT-003 CRITICAL  Tainted SQL sink      path=request.args → f-string → execute" },
        { t: 980, s: "• GR-TAINT-001 CRITICAL  Tainted eval/exec     path=form.expr → eval" },
        { t: 1320, s: "• GR-AST-003   CRITICAL  Dynamic code execution" },
        { t: 1680, s: "• GR-TS-PY-001 CRITICAL  tree-sitter eval call" },
        {
          t: 2100,
          s:
            "\n────────────────────────────────────\nsecurity_verdict : REJECTED\nrisk_score        : 205\npolicy_decision   : DENY  (strict pack)\nsecurity_score    : 28 / F\nremediation       : 5 fix drafts ready",
        },
      ];
      lines.forEach(({ t, s }) => {
        setTimeout(() => {
          demoOut.textContent += s + "\n";
          demoOut.scrollTop = demoOut.scrollHeight;
        }, t);
      });
      setTimeout(() => {
        if (scoreVal) scoreVal.textContent = "28";
        if (scoreRing) scoreRing.style.setProperty("--p", "28%");
        if (verdictVal) {
          verdictVal.textContent = "REJECTED";
          verdictVal.className = "v-bad";
        }
        if (enginesVal) enginesVal.textContent = "5 engines";
        if (issuesVal) issuesVal.textContent = "5 findings";
        if (policyVal) {
          policyVal.textContent = "DENY";
          policyVal.className = "v-bad";
        }
        runBtn.disabled = false;
        runBtn.textContent = "Run live demo";
        showToast("Hybrid scan complete");
      }, 2300);
    });
  }
})();
