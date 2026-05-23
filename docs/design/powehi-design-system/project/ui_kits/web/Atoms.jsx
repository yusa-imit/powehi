// Powehi · Atoms — Logo (Gargantua silhouette), Avatar, Button, IconBtn, Pill

function Logo({ size = 32, withWord = false }) {
  const u = `pw-${size}`;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
      <svg width={size} height={size} viewBox="0 0 256 256" fill="none">
        <defs>
          <radialGradient id={`h-${u}`} cx="50%" cy="50%" r="50%">
            <stop offset="0%"  stopColor="#FFB155"/>
            <stop offset="30%" stopColor="#FF8A3D"/>
            <stop offset="60%" stopColor="#C75612" stopOpacity="0.7"/>
            <stop offset="100%" stopColor="#3A1A06" stopOpacity="0"/>
          </radialGradient>
        </defs>
        <ellipse cx="128" cy="128" rx="124" ry="84" fill={`url(#h-${u})`}/>
        <circle cx="128" cy="128" r="46" fill="#000000"/>
        <circle cx="128" cy="128" r="46" fill="none" stroke="#E8F0FF" strokeWidth="1.4"/>
      </svg>
      {withWord && (
        <span style={{
          fontFamily: 'Geist, system-ui, sans-serif',
          fontWeight: 600,
          fontSize: size * 0.66,
          letterSpacing: '-0.03em',
          color: 'var(--fg-1)',
        }}>powehi</span>
      )}
    </span>
  );
}

const PALETTE = [
  ['#A8C8FF', '#445C99'],
  ['#FF8A3D', '#6E2700'],
  ['#5EE6A8', '#1F6B4C'],
  ['#FFD78A', '#B14507'],
  ['#C8DCFF', '#6688CC'],
  ['#FF9E52', '#B14507'],
];

function avatarColors(seed) {
  const i = (seed || '').split('').reduce((a, c) => a + c.charCodeAt(0), 0) % PALETTE.length;
  return PALETTE[i];
}

function Avatar({ name, size = 40, online }) {
  const initials = (name || '?').split(' ').map(s => s[0]).join('').slice(0, 2).toUpperCase();
  const [a, b] = avatarColors(name);
  // Cool gradients use dark text; warm gradients use light text
  const isCool = a === '#A8C8FF' || a === '#C8DCFF' || a === '#5EE6A8' || a === '#FFD78A';
  return (
    <span style={{ position: 'relative', width: size, height: size, flex: 'none', display: 'inline-block' }}>
      <span style={{
        width: size, height: size, borderRadius: '50%',
        background: `linear-gradient(135deg, ${a}, ${b})`,
        color: isCool ? '#06060C' : '#fff',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontWeight: 600, fontSize: size * 0.38,
      }}>{initials}</span>
      {online !== undefined && (
        <span style={{
          position: 'absolute', bottom: -1, right: -1,
          width: Math.max(10, size * 0.28), height: Math.max(10, size * 0.28),
          borderRadius: '50%',
          background: online ? '#5EE6A8' : 'var(--fg-4)',
          border: `${Math.max(2, size * 0.06)}px solid var(--bg-void)`,
          boxShadow: online ? '0 0 6px rgba(94,230,168,0.5)' : 'none',
        }}/>
      )}
    </span>
  );
}

function Button({ variant = 'primary', size = 'md', icon, iconRight, children, onClick, style, disabled }) {
  const sizes = {
    sm: { padding: '7px 12px', fontSize: 13, borderRadius: 8 },
    md: { padding: '10px 16px', fontSize: 14, borderRadius: 10 },
    lg: { padding: '13px 20px', fontSize: 15, borderRadius: 12 },
  };
  const variants = {
    primary: {
      background: 'linear-gradient(180deg, #FF9E52, #FF7A2B)',
      color: '#2A0A00',
      boxShadow: '0 0 0 1px rgba(255,138,61,0.35), 0 0 18px rgba(255,138,61,0.25), inset 0 1px 0 rgba(255,255,255,0.25)',
      border: '1px solid transparent',
    },
    secondary: { background: 'var(--bg-elevated)', color: 'var(--fg-1)', border: '1px solid var(--border-soft)' },
    ghost:     { background: 'transparent', color: 'var(--fg-2)', border: '1px solid transparent' },
    photon:    { background: 'rgba(168,200,255,0.10)', color: '#C8DCFF', border: '1px solid rgba(168,200,255,0.3)' },
    danger:    { background: 'transparent', color: '#FF9999', border: '1px solid rgba(255,122,122,0.3)' },
  };
  return (
    <button onClick={onClick} disabled={disabled}
      style={{
        ...sizes[size], ...variants[variant],
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 8,
        fontFamily: 'var(--font-sans)', fontWeight: 500,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        transition: 'all 200ms cubic-bezier(0.22, 1, 0.36, 1)',
        whiteSpace: 'nowrap',
        ...style,
      }}>
      {icon && <Icon name={icon} size={size === 'sm' ? 14 : 16}/>}
      {children}
      {iconRight && <Icon name={iconRight} size={size === 'sm' ? 14 : 16}/>}
    </button>
  );
}

function IconBtn({ icon, onClick, active, size = 36, label, style, color }) {
  const [hover, setHover] = React.useState(false);
  return (
    <button onClick={onClick} aria-label={label}
      onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      style={{
        width: size, height: size, borderRadius: 10,
        background: active ? 'var(--bg-elevated)' : (hover ? 'var(--bg-surface)' : 'transparent'),
        color: color || (active ? 'var(--accretion-400)' : 'var(--fg-2)'),
        border: '1px solid transparent',
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        cursor: 'pointer',
        transition: 'all 200ms cubic-bezier(0.22, 1, 0.36, 1)',
        ...style,
      }}>
      <Icon name={icon} size={size * 0.5}/>
    </button>
  );
}

function Pill({ children, variant = 'default', icon }) {
  const variants = {
    default:   { background: 'transparent', color: 'var(--fg-3)', border: '1px solid var(--border-soft)' },
    photon:    { background: 'rgba(168,200,255,0.14)', color: '#C8DCFF', border: '1px solid rgba(168,200,255,0.3)' },
    online:    { background: 'rgba(94,230,168,0.12)',  color: '#5EE6A8', border: '1px solid rgba(94,230,168,0.3)' },
    accretion: { background: 'rgba(255,138,61,0.12)',  color: '#FF9E52', border: '1px solid rgba(255,138,61,0.3)' },
  };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      padding: '4px 10px', borderRadius: 9999,
      fontSize: 11, fontWeight: 500, letterSpacing: '0.04em',
      ...variants[variant],
    }}>
      {icon && <Icon name={icon} size={11}/>}
      {children}
    </span>
  );
}

Object.assign(window, { Logo, Avatar, Button, IconBtn, Pill });
