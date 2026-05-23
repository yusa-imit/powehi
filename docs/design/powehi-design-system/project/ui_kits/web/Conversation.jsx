// Powehi · Conversation — header, messages, composer

function ConversationHeader({ chat, onCall, onVideo, onInfo, infoOpen }) {
  return (
    <header style={{
      height: 64, flex: 'none', padding: '0 18px',
      borderBottom: '1px solid var(--border-soft)',
      display: 'flex', alignItems: 'center', gap: 14,
      background: 'var(--bg-void)',
    }}>
      <Avatar name={chat.name} size={38} online={chat.online}/>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 15, fontWeight: 500, color: 'var(--fg-1)' }}>{chat.name}</span>
          <Icon name="lock" size={11} color="#A8C8FF"/>
        </div>
        <div style={{ fontSize: 11, color: 'var(--fg-3)', marginTop: 1 }}>
          {chat.online ? 'online' : `last seen ${chat.lastSeen || 'recently'}`}
          {chat.typing && <span style={{ color: '#FF9E52', marginLeft: 8, fontStyle: 'italic' }}>· typing</span>}
        </div>
      </div>
      <div style={{ display: 'flex', gap: 2 }}>
        <IconBtn icon="phone" onClick={onCall} label="Voice call"/>
        <IconBtn icon="video" onClick={onVideo} label="Video call"/>
        <IconBtn icon="more" onClick={onInfo} active={infoOpen} label="Info"/>
      </div>
    </header>
  );
}

function MessageList({ messages, partner }) {
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [messages.length]);

  const groups = [];
  let lastDay = null;
  messages.forEach(m => {
    if (m.day !== lastDay && m.day) {
      groups.push({ type: 'day', label: m.day });
      lastDay = m.day;
    }
    groups.push({ type: 'msg', msg: m });
  });

  return (
    <div ref={ref}
      style={{
        flex: 1, overflowY: 'auto',
        padding: '24px 36px 16px',
        display: 'flex', flexDirection: 'column', gap: 4,
        background: 'radial-gradient(ellipse 100% 60% at 50% 110%, rgba(255,138,61,0.07), transparent 60%), var(--bg-void)',
      }}>
      <div style={{
        alignSelf: 'center', maxWidth: 480, textAlign: 'center',
        padding: '14px 20px', margin: '8px 0 24px',
        background: 'rgba(168,200,255,0.05)',
        border: '1px solid rgba(168,200,255,0.18)',
        borderRadius: 12,
      }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          fontSize: 11, fontWeight: 500, letterSpacing: '0.12em',
          color: '#C8DCFF', textTransform: 'uppercase', marginBottom: 6,
        }}>
          <Icon name="lock" size={11}/> End-to-end encrypted
        </div>
        <div style={{ fontSize: 12, color: 'var(--fg-3)', lineHeight: 1.5 }}>
          Only you and {partner.split(' ')[0]} can read these messages. Not even Powehi.
        </div>
      </div>
      {groups.map((g, i) => g.type === 'day' ? (
        <div key={i} style={{
          alignSelf: 'center', margin: '12px 0 6px',
          fontSize: 10, fontWeight: 500, letterSpacing: '0.14em',
          color: 'var(--fg-4)', textTransform: 'uppercase',
        }}>{g.label}</div>
      ) : (
        <MessageBubble key={i} msg={g.msg} partner={partner}/>
      ))}
    </div>
  );
}

function MessageBubble({ msg, partner }) {
  const isMe = msg.from === 'me';
  return (
    <div style={{
      display: 'flex', justifyContent: isMe ? 'flex-end' : 'flex-start',
      alignItems: 'flex-end', gap: 8, marginTop: msg.continued ? 2 : 8,
    }}>
      {!isMe && (
        <div style={{ width: 28, flex: 'none' }}>
          {!msg.continued && <Avatar name={partner} size={28}/>}
        </div>
      )}
      <div style={{
        maxWidth: '72%',
        padding: '10px 14px',
        fontSize: 14, lineHeight: 1.45,
        borderRadius: 18,
        ...(isMe ? {
          background: 'linear-gradient(135deg, #FF9E52, #F26F1F)',
          color: '#2A1100',
          borderBottomRightRadius: msg.last ? 6 : 18,
          boxShadow: '0 0 18px rgba(255,138,61,0.18)',
        } : {
          background: 'var(--bg-elevated)',
          color: 'var(--fg-1)',
          border: '1px solid var(--border-faint)',
          borderBottomLeftRadius: msg.last ? 6 : 18,
        }),
      }}>
        {msg.text}
        {msg.last && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            marginLeft: 8, opacity: 0.7,
            fontSize: 10, fontFamily: 'var(--font-mono)',
            verticalAlign: '2px',
          }}>
            {msg.time}
            {isMe && <Icon name="doublecheck" size={12} color={msg.read ? '#A8C8FF' : 'currentColor'}/>}
          </span>
        )}
      </div>
    </div>
  );
}

function Composer({ onSend, partner }) {
  const [text, setText] = React.useState('');
  const send = () => {
    if (text.trim()) { onSend(text.trim()); setText(''); }
  };
  return (
    <div style={{ flex: 'none', padding: '12px 24px 18px', background: 'var(--bg-void)' }}>
      <div style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-soft)',
        borderRadius: 16,
        display: 'flex', alignItems: 'flex-end', gap: 4,
        padding: '6px 6px 6px 14px',
        boxShadow: 'var(--shadow-md)',
      }}>
        <IconBtn icon="attach" label="Attach" size={32}/>
        <IconBtn icon="image" label="Photo" size={32}/>
        <textarea value={text}
          onChange={e => setText(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
          }}
          placeholder={`Message ${partner.split(' ')[0]} — encrypted`}
          rows={1}
          style={{
            flex: 1, background: 'transparent', border: 'none', outline: 'none',
            color: 'var(--fg-1)', fontFamily: 'var(--font-sans)', fontSize: 14,
            resize: 'none', padding: '8px 8px 8px 4px',
            maxHeight: 120, lineHeight: 1.4,
          }}/>
        <IconBtn icon="smile" label="Emoji" size={32}/>
        {text.trim() ? (
          <button onClick={send}
            style={{
              width: 36, height: 36, borderRadius: '50%', border: 'none',
              background: 'linear-gradient(180deg, #FF9E52, #FF7A2B)',
              color: '#2A0A00',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              cursor: 'pointer',
              boxShadow: '0 0 0 1px rgba(255,138,61,0.35), 0 0 14px rgba(255,138,61,0.3)',
              transition: 'transform 120ms',
            }}
            onMouseDown={e => e.currentTarget.style.transform = 'scale(0.94)'}
            onMouseUp={e => e.currentTarget.style.transform = 'scale(1)'}>
            <Icon name="arrowRight" size={16}/>
          </button>
        ) : (
          <IconBtn icon="mic" label="Voice" size={36}/>
        )}
      </div>
    </div>
  );
}

Object.assign(window, { ConversationHeader, MessageList, MessageBubble, Composer });
