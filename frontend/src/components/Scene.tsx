/**
 * Neon backdrop: glow fields, a threat-intel constellation and a perspective grid.
 * Original artwork drawn in code. An optional photo at /backgrounds/custom.jpg is
 * blended underneath when present (a missing file simply shows nothing).
 */

// Fixed pseudo-random node positions so the picture is identical on every load.
const NODES: [number, number][] = [
  [70, 120], [180, 60], [260, 170], [390, 90], [520, 140], [640, 60], [760, 160], [880, 80], [1010, 150],
  [1130, 70], [1250, 140], [1360, 90], [120, 260], [330, 300], [470, 250], [610, 320], [730, 260], [900, 300],
  [1060, 260], [1200, 320], [1340, 250], [40, 420], [220, 450], [420, 400], [980, 430], [1180, 460], [1390, 410],
];
const EDGES: [number, number][] = [
  [0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 8], [8, 9], [9, 10], [10, 11], [0, 12], [12, 13],
  [2, 13], [13, 14], [4, 14], [14, 15], [15, 16], [6, 16], [16, 17], [7, 17], [17, 18], [8, 18], [18, 19],
  [19, 20], [11, 20], [12, 21], [21, 22], [22, 23], [13, 23], [18, 24], [24, 25], [19, 25], [25, 26], [20, 26],
];
const HOT = new Set([4, 13, 17, 24]); // a few nodes glow red: threats in the graph

export function Scene() {
  return (
    <div className="scene pointer-events-none fixed inset-0 -z-10 overflow-hidden" aria-hidden>
      <div
        className="absolute inset-0 bg-cover bg-center opacity-[0.22] mix-blend-screen"
        style={{ backgroundImage: "url(/backgrounds/custom.jpg)" }}
      />
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(60% 50% at 78% 18%, rgb(0 229 255 / 0.16), transparent 70%)," +
            "radial-gradient(45% 40% at 10% 85%, rgb(124 92 255 / 0.16), transparent 70%)," +
            "radial-gradient(35% 30% at 92% 92%, rgb(255 59 92 / 0.10), transparent 70%)",
        }}
      />
      <svg className="absolute inset-x-0 top-0 h-[520px] w-full opacity-60" viewBox="0 0 1440 520" preserveAspectRatio="xMidYMin slice">
        <defs>
          <radialGradient id="node-c"><stop offset="0" stopColor="rgb(0 229 255)" stopOpacity="1" /><stop offset="1" stopColor="rgb(0 229 255)" stopOpacity="0" /></radialGradient>
          <radialGradient id="node-r"><stop offset="0" stopColor="rgb(255 59 92)" stopOpacity="1" /><stop offset="1" stopColor="rgb(255 59 92)" stopOpacity="0" /></radialGradient>
          <linearGradient id="fade" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="white" /><stop offset="1" stopColor="white" stopOpacity="0" /></linearGradient>
          <mask id="fade-mask"><rect width="1440" height="520" fill="url(#fade)" /></mask>
        </defs>
        <g mask="url(#fade-mask)">
          <g stroke="rgb(0 229 255)" strokeOpacity="0.18" strokeWidth="1">
            {EDGES.map(([a, b]) => (
              <line key={`${a}-${b}`} x1={NODES[a][0]} y1={NODES[a][1]} x2={NODES[b][0]} y2={NODES[b][1]} />
            ))}
          </g>
          {NODES.map(([x, y], i) => (
            <g key={i}>
              <circle cx={x} cy={y} r={HOT.has(i) ? 14 : 9} fill={`url(#node-${HOT.has(i) ? "r" : "c"})`} opacity="0.55" />
              <circle cx={x} cy={y} r={HOT.has(i) ? 2.6 : 1.8} fill={HOT.has(i) ? "rgb(255 59 92)" : "rgb(160 245 255)"} />
            </g>
          ))}
        </g>
      </svg>
      <div
        className="absolute inset-x-0 bottom-0 h-[42vh] opacity-40"
        style={{
          backgroundImage:
            "linear-gradient(rgb(0 229 255 / 0.22) 1px, transparent 1px), linear-gradient(90deg, rgb(0 229 255 / 0.22) 1px, transparent 1px)",
          backgroundSize: "56px 56px",
          transform: "perspective(420px) rotateX(62deg)",
          transformOrigin: "bottom",
          maskImage: "linear-gradient(to top, black 10%, transparent 85%)",
          WebkitMaskImage: "linear-gradient(to top, black 10%, transparent 85%)",
        }}
      />
      <div className="absolute inset-0" style={{ background: "linear-gradient(to bottom, transparent 55%, rgb(4 7 18 / 0.6))" }} />
    </div>
  );
}
