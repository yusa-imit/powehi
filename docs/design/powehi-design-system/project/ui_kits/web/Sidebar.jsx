// Powehi · Sidebar — brand bar, search, chat list, encryption banner

function Sidebar({ chats, activeId, onSelect, onNewChat, onSettings, onSearch, searchQuery }) {
  const filtered = chats.filter(c =>
    !searchQuery || c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (c.last || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <aside style={{
      width: 320, flex: 'none',
      background: 'var(--bg-surface)',
      borderRight: '1px solid var(--border-soft)',
      display: 'flex', flexDirection: 'column', height: '100%',
    }}>
      <div style={{
        padding: '18px 18px 14px',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <Logo size={28} withWord/>
        <div style={{ display: 'flex', gap: 2 }}>
          <IconBtn icon="plus" onClick={onNewChat} label="New chat"/>
          <IconBtn icon="settings" onClick={onSettings} label="Settings"/>
        </div>
      </div>

      <div style={{ padding: '0 14px 12px' }}>
        <div style={{
          background: 'var(--bg-input)', borderRadius: 10,
          border: '1px solid var(--border-faint)',
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '8px 12px',
        }}>
          <Icon name="search" size={15} color="var(--fg-3)"/>
          <input value={searchQuery || ''} onChange={e => onSearch(e.target.value)}
            placeholder="Search chats"
            style={{
              flex: 1, background: 'transparent', border: 'none', outline: 'none',
              color: 'var(--fg-1)', fontFamily: 'var(--font-sans)', fontSize: 13,
            }}/>
        </div>
      </div>

      {/* Encryption banner — photon blue */}
      <div style={{
        margin: '0 14px 8px', padding: '8px 12px',
        background: 'rgba(168,200,255,0.05)',
        border: '1px solid rgba(168,200,255,0.16)',
        borderRadius: 10,
        display: 'flex', alignItems: 'center', gap: 9,
        fontSize: 11, color: '#C8DCFF', letterSpacing: '0.04em',
      }}>
        <Icon name="lock" size={13}/>
        <span style={{ fontWeight: 500 }}>END-TO-END ENCRYPTED</span>
        <span style={{ marginLeft: 'auto', opacity: 0.7 }}>·</span>
        <span style={{ opacity: 0.85 }}>only you</span>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '6px 8px 12px' }}>
        {filtered.map(c => (
          <ChatRow key={c.id} chat={c} active={c.id === activeId} onClick={() => onSelect(c.id)}/>
        ))}
        {filtered.length === 0 && (
          <div style={{ padding: 24, textAlign: 'center', color: 'var(--fg-3)', fontSize: 13 }}>
            No chats match "{searchQuery}".
          </div>
        )}
      </div>
    </aside>
  );
}

function ChatRow({ chat, active, onClick }) {
  const [hover, setHover] = React.useState(false);
  return (
    <div onClick={onClick}
      onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex', alignItems: 'center', gap: 12,
        padding: '11px 12px', borderRadius: 12, cursor: 'pointer',
        background: active ? 'var(--bg-elevated)' : (hover ? 'var(--bg-surface)' : 'transparent'),
        transition: 'background 120ms',
      }}>
      <Avatar name={chat.name} size={42} online={chat.online}/>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
          <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--fg-1)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{chat.name}</span>
          <span style={{ fontSize: 11, color: 'var(--fg-3)',
            fontFamily: 'var(--font-mono)', flex: 'none' }}>{chat.time}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2 }}>
          {chat.typing ? (
            <span style={{ fontSize: 13, color: '#FF9E52', fontStyle: 'italic' }}>typing…</span>
          ) : (
            <span style={{ fontSize: 13, color: active ? 'var(--fg-2)' : 'var(--fg-3)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{chat.last}</span>
          )}
          {chat.unread > 0 && (
            <span style={{
              background: '#FF8A3D', color: '#2A0A00',
              fontWeight: 600, fontSize: 10, borderRadius: 9999,
              padding: '2px 7px', flex: 'none',
            }}>{chat.unread}</span>
          )}
        </div>
      </div>
    </div>
  );
}

window.Sidebar = Sidebar;
