/* SPY-THREAT-HUNT V2 — signature background:
   a drifting "signal web" of nodes + connective threads, with occasional
   pulse packets traveling along the strands (a quiet nod to the SPYDIR
   brand without being literal about it). Respects reduced-motion. */
(function () {
  const canvas = document.getElementById("web-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  let W, H, DPR;
  let nodes = [];
  let pulses = [];

  function resize() {
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = W * DPR;
    canvas.height = H * DPR;
    canvas.style.width = W + "px";
    canvas.style.height = H + "px";
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    initNodes();
  }

  function initNodes() {
    const count = Math.max(24, Math.min(60, Math.floor((W * H) / 34000)));
    nodes = [];
    for (let i = 0; i < count; i++) {
      nodes.push({
        x: Math.random() * W,
        y: Math.random() * H,
        vx: (Math.random() - 0.5) * 0.14,
        vy: (Math.random() - 0.5) * 0.14,
        r: 1 + Math.random() * 1.6,
      });
    }
  }

  function maybeSpawnPulse() {
    if (Math.random() > 0.985 && nodes.length > 2) {
      const a = nodes[Math.floor(Math.random() * nodes.length)];
      const b = nodes[Math.floor(Math.random() * nodes.length)];
      if (a !== b) pulses.push({ a, b, t: 0, speed: 0.006 + Math.random() * 0.01 });
    }
  }

  const LINK_DIST = 150;
  const CYAN = "46,230,214";
  const VIOLET = "124,108,255";

  function step() {
    ctx.clearRect(0, 0, W, H);

    // drift
    for (const n of nodes) {
      n.x += n.vx;
      n.y += n.vy;
      if (n.x < -20) n.x = W + 20;
      if (n.x > W + 20) n.x = -20;
      if (n.y < -20) n.y = H + 20;
      if (n.y > H + 20) n.y = -20;
    }

    // links
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < LINK_DIST) {
          const alpha = (1 - dist / LINK_DIST) * 0.16;
          ctx.strokeStyle = `rgba(${CYAN},${alpha})`;
          ctx.lineWidth = 0.6;
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.stroke();
        }
      }
    }

    // nodes
    for (const n of nodes) {
      ctx.beginPath();
      ctx.fillStyle = `rgba(${CYAN},0.55)`;
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();
    }

    // pulses
    if (!reduceMotion) maybeSpawnPulse();
    pulses = pulses.filter((p) => p.t <= 1);
    for (const p of pulses) {
      p.t += p.speed;
      const x = p.a.x + (p.b.x - p.a.x) * p.t;
      const y = p.a.y + (p.b.y - p.a.y) * p.t;
      const grd = ctx.createRadialGradient(x, y, 0, x, y, 6);
      grd.addColorStop(0, `rgba(${VIOLET},0.9)`);
      grd.addColorStop(1, `rgba(${VIOLET},0)`);
      ctx.fillStyle = grd;
      ctx.beginPath();
      ctx.arc(x, y, 6, 0, Math.PI * 2);
      ctx.fill();
    }

    if (!reduceMotion) requestAnimationFrame(step);
  }

  window.addEventListener("resize", resize);
  resize();
  step();
  if (reduceMotion) {
    // draw a single static frame
    step();
  }
})();
