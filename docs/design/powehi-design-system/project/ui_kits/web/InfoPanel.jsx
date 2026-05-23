// Powehi · Right info panel

function InfoPanel({ chat, onClose }) {
  return (
    <aside style={{
      width: 340, flex: 'none',
      background: 'var(--bg-surface)',
      borderLeft: '1px solid var(--border-soft)',
      display: 'flex', flexDirection: 'column', height: '100%',
      overflowY: 'auto',
    }}>
      <div style={{
        padding: '14px 18px',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        borderBottom: '1px solid var(--border-faint)',
      }}>
        <span style={{ fontSize: 11, fontWeight: 500, letterSpacing: '0.14em',
          textTransform: 'uppercase', color: 'var(--fg-3)' }}>Conversation</span>
        <IconBtn icon="x" onClick={onClose} label="Close" size={28}/>
      </div>

      <div style={{ padding: '24px 18px 20px', textAlign: 'center' }}>
        <Avatar name={chat.name} size={80}/>
        <div style={{ fontSize: 18, fontWeight: 500, color: 'var(--fg-1)', marginTop: 14 }}>{chat.name}</div>
        <div style={{ fontSize: 13, color: 'var(--fg-3)', marginTop: 4 }}>
          @{chat.handle || chat.name.toLowerCase().replace(/\s+/g, '')}
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 16 }}>
          <Button variant="secondary" size="sm" icon="phone">Call</Button>
          <Button variant="secondary" size="sm" icon="video">Video</Button>
        </div>
      </div>

      <div style={{ padding: '0 14px 16px' }}>
        <div style={{
          background: 'rgba(168,200,255,0.05)',
          border: '1px solid rgba(168,200,255,0.22)',
          borderRadius: 14, padding: 16,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: 10,
              background: 'rgba(168,200,255,0.14)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: '#A8C8FF',
            }}>
              <Icon name="lock" size={16}/>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--fg-1)' }}>End-to-end encrypted</div>
              <div style={{ fontSize: 11, color: '#C8DCFF', letterSpacing: '0.04em' }}>
                VERIFIED · {chat.verifiedAgo || '2 days ago'}
              </div>
            </div>
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-2)',
            background: 'var(--bg-input)',
            border: '1px solid var(--border-faint)',
            borderRadius: 8, padding: '8px 10px',
            letterSpacing: '0.02em', textAlign: 'center', lineHeight: 1.6,
          }}>
            A3:5F:91:CC:7E:08<br/>
            72:1B:E4:88:3D:F0
          </div>
          <button style={{
            width: '100%', marginTop: 10,
            background: 'transparent', border: '1px solid rgba(168,200,255,0.3)',
            color: '#C8DCFF', borderRadius: 9,
            padding: '7px', fontFamily: 'var(--font-sans)', fontSize: 12,
            fontWeight: 500, cursor: 'pointer',
          }}>Compare in person</button>
        </div>
      </div>

      <Section title="Notifications">
        <Row label="Mute" trailing="Off"/>
        <Row label="Pin to top" trailing="On"/>
      </Section>
      <Section title="Disappearing messages">
        <Row label="Auto-delete after" trailing="1 week"/>
      </Section>
      <Section title="Media">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6, padding: '4px 18px 16px' }}>
          {[0,1,2,3,4,5].map(i => (
            <div key={i} style={{
              aspectRatio: '1/1', borderRadius: 8,
              background: `linear-gradient(135deg, hsl(${i*40 + 20}, 40%, 28%), hsl(${i*40 + 220}, 35%, 10%))`,
            }}/>
          ))}
        </div>
      </Section>

      <div style={{ padding: '8px 18px 24px', display: 'flex', flexDirection: 'column', gap: 4 }}>
        <button style={destructiveButton}>Clear messages</button>
        <button style={destructiveButton}>Block · Report</button>
      </div>
    </aside>
  );
}

const destructiveButton = {
  textAlign: 'left', background: 'transparent', border: 'none',
  color: '#FF9999', padding: '10px 0', fontFamily: 'var(--font-sans)',
  fontSize: 13, fontWeight: 500, cursor: 'pointer',
};

function Section({ title, children }) {
  return (
    <div style={{ borderTop: '1px solid var(--border-faint)' }}>
      <div style={{
        fontSize: 10, fontWeight: 500, letterSpacing: '0.14em',
        textTransform: 'uppercase', color: 'var(--fg-3)',
        padding: '14px 18px 4px',
      }}>{title}</div>
      {children}
    </div>
  );
}

function Row({ label, trailing }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 18px', fontSize: 13 }}>
      <span style={{ color: 'var(--fg-1)' }}>{label}</span>
      <span style={{ color: 'var(--fg-3)' }}>{trailing}</span>
    </div>
  );
}

window.InfoPanel = InfoPanel;
