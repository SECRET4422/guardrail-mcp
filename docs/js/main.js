(function () {
  const menuBtn = document.getElementById("menuBtn");
  const navLinks = document.getElementById("navLinks");
  const navCta = document.getElementById("navCta");
  if (menuBtn) {
    menuBtn.addEventListener("click", () => {
      navLinks.classList.toggle("open");
      navCta.classList.toggle("open");
    });
  }

  const toast = document.getElementById("toast");
  function showToast(msg) {
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 1800);
  }

  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const sel = btn.getAttribute("data-copy");
      const el = document.querySelector(sel);
      if (!el) return;
      const text = el.innerText || el.textContent;
      try {
        await navigator.clipboard.writeText(text);
        showToast("Copied to clipboard");
      } catch {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
        showToast("Copied to clipboard");
      }
    });
  });

  // Live demo: fake scan animation
  const runBtn = document.getElementById("runDemo");
  const demoOut = document.getElementById("demoOut");
  const scoreVal = document.getElementById("scoreVal");
  const verdictVal = document.getElementById("verdictVal");
  const enginesVal = document.getElementById("enginesVal");
  const issuesVal = document.getElementById("issuesVal");

  const sample = `def login(request):
    password = "SuperSecretValue99"
    q = request.args.get("user")
    db.execute(f"SELECT * FROM users WHERE name='{q}'")
    eval(request.form.get("expr"))
    return "ok"`;

  if (runBtn && demoOut) {
    runBtn.addEventListener("click", () => {
      runBtn.disabled = true;
      runBtn.textContent = "Scanning…";
      demoOut.textContent = "→ hybrid_scan(source, engines=['regex','ast','taint','treesitter'])\n";
      const lines = [
        { t: 300, s: "• GR-SEC-002  HIGH      hardcoded credential assignment" },
        { t: 700, s: "• GR-TAINT-003 CRITICAL  tainted SQL sink (request → execute)" },
        { t: 1100, s: "• GR-TAINT-001 CRITICAL  tainted eval/exec" },
        { t: 1500, s: "• GR-AST-003  CRITICAL  dynamic code execution" },
        { t: 1900, s: "\nsecurity_verdict: REJECTED\nrisk_score: 180\npolicy_decision: DENY\nengines: regex + ast + taint + treesitter" },
      ];
      lines.forEach(({ t, s }) => {
        setTimeout(() => {
          demoOut.textContent += (demoOut.textContent.endsWith("\n") || !demoOut.textContent ? "" : "\n") + s + "\n";
          demoOut.scrollTop = demoOut.scrollHeight;
        }, t);
      });
      setTimeout(() => {
        if (scoreVal) scoreVal.textContent = "28";
        if (verdictVal) {
          verdictVal.textContent = "REJECTED";
          verdictVal.className = "v-bad";
        }
        if (enginesVal) enginesVal.textContent = "4 engines";
        if (issuesVal) issuesVal.textContent = "4 findings";
        runBtn.disabled = false;
        runBtn.textContent = "Run live demo";
        showToast("Demo scan complete");
      }, 2100);
    });
  }

  // Year
  const y = document.getElementById("year");
  if (y) y.textContent = String(new Date().getFullYear());
})();
