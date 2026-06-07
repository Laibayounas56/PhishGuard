(function () {
  const POPUP_ID = "phishguard-status-popup";

  function makeButton(text, styles) {
    const button = document.createElement("button");
    button.textContent = text;
    button.style.cssText = styles;
    return button;
  }

  function injectPopup({ status, score }) {
    if (!document.body) return;

    const existing = document.getElementById(POPUP_ID);
    if (existing) existing.remove();

    const isSafe = status === "Safe";
    const accent = isSafe ? "#10b981" : "#f59e0b";
    const bg = isSafe ? "#052e24" : "#2f1d05";
    const border = isSafe ? "rgba(16,185,129,.38)" : "rgba(245,158,11,.42)";
    const text = isSafe ? "#ecfdf5" : "#fef3c7";
    const muted = isSafe ? "#bbf7d0" : "#fde68a";

    const popup = document.createElement("div");
    popup.id = POPUP_ID;
    popup.style.cssText = [
      "position:fixed",
      "top:22px",
      "right:22px",
      "width:min(360px,calc(100vw - 32px))",
      "z-index:2147483647",
      `background:${bg}`,
      `border:1px solid ${border}`,
      "border-radius:10px",
      "box-shadow:0 18px 55px rgba(0,0,0,.38)",
      `color:${text}`,
      "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif",
      "padding:18px",
      "box-sizing:border-box",
    ].join(";");

    const topRow = document.createElement("div");
    topRow.style.cssText = "display:flex;align-items:flex-start;gap:12px";

    const mark = document.createElement("div");
    mark.textContent = isSafe ? "OK" : "!";
    mark.style.cssText = [
      "display:grid",
      "place-items:center",
      "width:42px",
      "height:42px",
      "flex:0 0 42px",
      `border:1px solid ${border}`,
      "border-radius:8px",
      `background:${isSafe ? "rgba(16,185,129,.16)" : "rgba(245,158,11,.16)"}`,
      `color:${accent}`,
      "font-weight:900",
      "font-size:15px",
    ].join(";");

    const copy = document.createElement("div");
    copy.style.cssText = "min-width:0;flex:1";

    const title = document.createElement("strong");
    title.textContent = isSafe ? "PhishGuard scanned this page" : "PhishGuard warning";
    title.style.cssText = "display:block;margin:0 0 5px;font-size:16px;line-height:1.25";

    const detail = document.createElement("div");
    detail.textContent = isSafe
      ? `Safe URL. Threat score: ${score}/100.`
      : `Suspicious URL. Threat score: ${score}/100. Proceed only if you trust this site.`;
    detail.style.cssText = `color:${muted};font-size:13px;line-height:1.45`;

    const closeX = makeButton(
      "x",
      `border:0;background:transparent;color:${muted};cursor:pointer;font-size:18px;line-height:1;padding:0 2px;font-weight:800`
    );
    closeX.setAttribute("aria-label", "Close PhishGuard popup");
    closeX.addEventListener("click", () => popup.remove());

    const actions = document.createElement("div");
    actions.style.cssText = "display:flex;gap:8px;justify-content:flex-end;margin-top:16px;flex-wrap:wrap";

    const close = makeButton(
      isSafe ? "Got it" : "Proceed Anyway",
      `border:1px solid rgba(255,255,255,.28);border-radius:7px;background:transparent;color:${text};cursor:pointer;font-weight:800;padding:8px 13px;font-size:13px`
    );
    close.addEventListener("click", () => popup.remove());

    if (!isSafe) {
      const back = makeButton(
        "Go Back",
        "border:0;border-radius:7px;background:#f59e0b;color:#1c1917;cursor:pointer;font-weight:900;padding:8px 13px;font-size:13px"
      );
      back.addEventListener("click", () => history.back());
      actions.append(back);
    }

    actions.append(close);
    copy.append(title, detail);
    topRow.append(mark, copy, closeX);
    popup.append(topRow, actions);
    document.body.appendChild(popup);
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "PHISHGUARD_SAFE") {
      injectPopup({ status: "Safe", score: msg.score });
    }

    if (msg.type === "PHISHGUARD_WARNING") {
      injectPopup({ status: "Suspicious", score: msg.score });
    }
  });
})();
