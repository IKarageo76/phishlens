/** Original hero illustration: a hooded analyst at a laptop under a shield,
 * with threat markers orbiting. Pure SVG, so it stays sharp and themeable. */
export function HeroArt({ className = "" }: { className?: string }) {
  const cyan = "rgb(0 229 255)";
  const red = "rgb(255 59 92)";
  const violet = "rgb(124 92 255)";
  return (
    <svg viewBox="0 0 560 500" className={className} role="img" aria-label="Analyst at a laptop under a security shield">
      <defs>
        <radialGradient id="h-screenlight" cx="0.5" cy="0.1" r="0.8">
          <stop offset="0" stopColor={cyan} stopOpacity="0.55" />
          <stop offset="1" stopColor={cyan} stopOpacity="0" />
        </radialGradient>
        <linearGradient id="h-rim" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor={cyan} stopOpacity="0.9" />
          <stop offset="0.6" stopColor={violet} stopOpacity="0.5" />
          <stop offset="1" stopColor={violet} stopOpacity="0" />
        </linearGradient>
        <linearGradient id="h-body" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#0b1428" />
          <stop offset="1" stopColor="#04070f" />
        </linearGradient>
        <linearGradient id="h-face" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#000" />
          <stop offset="0.8" stopColor="#02070f" />
          <stop offset="1" stopColor="rgb(0 229 255)" stopOpacity="0.18" />
        </linearGradient>
        <filter id="h-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="6" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <filter id="h-soft"><feGaussianBlur stdDeviation="18" /></filter>
      </defs>

      {/* aura behind the figure */}
      <ellipse cx="280" cy="300" rx="210" ry="150" fill={cyan} opacity="0.10" filter="url(#h-soft)" />

      {/* orbit ring */}
      <ellipse cx="280" cy="170" rx="220" ry="62" fill="none" stroke={cyan} strokeOpacity="0.25" strokeDasharray="2 7" />

      {/* shield with lock */}
      <g transform="translate(280 70) scale(0.8)" filter="url(#h-glow)">
        <path d="M0 -62 L50 -44 L50 2 C50 34 28 56 0 68 C-28 56 -50 34 -50 2 L-50 -44 Z" fill="rgb(4 12 28 / 0.9)" stroke={cyan} strokeWidth="2.5" />
        <path d="M0 -48 L38 -34 L38 2 C38 26 22 43 0 53 C-22 43 -38 26 -38 2 L-38 -34 Z" fill="none" stroke={cyan} strokeOpacity="0.45" strokeWidth="1.2" />
        <rect x="-15" y="-6" width="30" height="24" rx="4" fill={cyan} />
        <path d="M-9 -6 V-14 a9 9 0 0 1 18 0 V-6" fill="none" stroke={cyan} strokeWidth="4" />
        <circle cx="0" cy="5" r="3.2" fill="#04070f" />
        <rect x="-1.4" y="5" width="2.8" height="7" fill="#04070f" />
      </g>

      {/* threat markers */}
      <g filter="url(#h-glow)">
        {/* warning */}
        <g transform="translate(78 168)">
          <polygon points="0,-30 26,-15 26,15 0,30 -26,15 -26,-15" fill="rgb(255 59 92 / 0.08)" stroke={red} strokeWidth="2" />
          <path d="M0 -13 L13 10 H-13 Z" fill="none" stroke={red} strokeWidth="2.2" strokeLinejoin="round" />
          <line x1="0" y1="-4" x2="0" y2="3" stroke={red} strokeWidth="2.2" />
          <circle cx="0" cy="7" r="1.3" fill={red} />
        </g>
        {/* magnifier */}
        <g transform="translate(150 62)">
          <polygon points="0,-26 22,-13 22,13 0,26 -22,13 -22,-13" fill="rgb(0 229 255 / 0.08)" stroke={cyan} strokeWidth="2" />
          <circle cx="-3" cy="-3" r="7.5" fill="none" stroke={cyan} strokeWidth="2.2" />
          <line x1="3" y1="3" x2="10" y2="10" stroke={cyan} strokeWidth="2.6" strokeLinecap="round" />
        </g>
        {/* bug */}
        <g transform="translate(470 74)">
          <polygon points="0,-26 22,-13 22,13 0,26 -22,13 -22,-13" fill="rgb(255 59 92 / 0.08)" stroke={red} strokeWidth="2" />
          <ellipse cx="0" cy="3" rx="6.5" ry="9" fill="none" stroke={red} strokeWidth="2" />
          <circle cx="0" cy="-9" r="3.5" fill="none" stroke={red} strokeWidth="2" />
          <path d="M-6 0 H-12 M6 0 H12 M-6 7 L-11 11 M6 7 L11 11 M-5 -5 L-10 -9 M5 -5 L10 -9" stroke={red} strokeWidth="1.8" strokeLinecap="round" />
        </g>
        {/* envelope */}
        <g transform="translate(498 196)">
          <polygon points="0,-24 20,-12 20,12 0,24 -20,12 -20,-12" fill="rgb(124 92 255 / 0.1)" stroke={violet} strokeWidth="2" />
          <rect x="-10" y="-7" width="20" height="14" rx="2" fill="none" stroke={violet} strokeWidth="1.8" />
          <path d="M-10 -6 L0 2 L10 -6" fill="none" stroke={violet} strokeWidth="1.8" />
        </g>
      </g>

      {/* connector lines from markers to the shield */}
      <g stroke={cyan} strokeOpacity="0.28" strokeWidth="1" fill="none">
        <path d="M104 160 Q190 130 232 118" />
        <path d="M172 70 Q220 80 250 64" />
        <path d="M448 80 Q380 70 314 70" />
        <path d="M478 196 Q400 170 330 128" />
      </g>

      {/* hooded figure */}
      <g transform="translate(0 28)">
        <path
          d="M70 530 C76 430 124 366 192 338 C176 300 170 248 182 196 C196 146 232 118 280 98 C328 118 364 146 378 196 C390 248 384 300 368 338 C436 366 484 430 490 530 Z"
          fill="url(#h-body)"
        />
        {/* rim light on the hood and shoulders */}
        <path
          d="M192 338 C176 300 170 248 182 196 C196 146 232 118 280 98 C328 118 364 146 378 196 C390 248 384 300 368 338"
          fill="none" stroke="url(#h-rim)" strokeWidth="2.2" opacity="0.9"
        />
        <path d="M192 338 C124 366 76 430 70 530" fill="none" stroke={cyan} strokeOpacity="0.35" strokeWidth="1.6" />
        <path d="M368 338 C436 366 484 430 490 530" fill="none" stroke={violet} strokeOpacity="0.35" strokeWidth="1.6" />
        {/* hood fold */}
        <path d="M222 182 C240 156 260 146 280 144 C300 146 320 156 338 182" fill="none" stroke={cyan} strokeOpacity="0.18" strokeWidth="1.4" />
        {/* face void, lit from below by the screen */}
        <path
          d="M232 252 C230 200 252 166 280 162 C308 166 330 200 328 252 C324 296 304 318 280 322 C256 318 236 296 232 252 Z"
          fill="url(#h-face)"
        />
        {/* screen light falling on the chest */}
        <ellipse cx="280" cy="372" rx="120" ry="44" fill="url(#h-screenlight)" />
      </g>

      {/* laptop seen from behind */}
      <g filter="url(#h-glow)" transform="translate(0 28)">
        <path d="M168 362 H392 L404 474 H156 Z" fill="#061022" stroke={cyan} strokeWidth="2" />
        <path d="M168 362 H392" stroke="rgb(180 250 255)" strokeWidth="2.4" />
        <rect x="140" y="474" width="280" height="10" rx="3" fill="#0a1830" stroke={cyan} strokeOpacity="0.6" />
        {/* small lens logo on the lid */}
        <circle cx="276" cy="414" r="11" fill="none" stroke={cyan} strokeWidth="2.4" />
        <line x1="284" y1="422" x2="293" y2="431" stroke={cyan} strokeWidth="2.8" strokeLinecap="round" />
        <line x1="270" y1="414" x2="282" y2="414" stroke={red} strokeWidth="2.2" strokeLinecap="round" />
      </g>
    </svg>
  );
}
