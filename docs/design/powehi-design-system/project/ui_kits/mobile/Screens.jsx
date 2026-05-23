// Powehi · Mobile screens — designed for 390-wide iOS frame

function MobileWelcome() {
  return (
    <div style={{
      height: '100%',
      background: 'radial-gradient(ellipse 80% 50% at 50% 30%, rgba(255,138,61,0.22), transparent 60%), radial-gradient(ellipse 40% 20% at 50% 30%, rgba(168,200,255,0.08), transparent 70%), #040408',
      display: 'flex', flexDirection: 'column',
      padding: '90px 28px 40px',
      color: '#F2EDE3', fontFamily: 'Geist, system-ui, sans-serif',
    }}>
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 28 }}>
        <Logo size={88}/>
      </div>
      <div style={{
        fontFamily: 'Instrument Serif, serif', fontStyle: 'italic',
        fontSize: 44, lineHeight: 1.05, textAlign: 'center',
        letterSpacing: '-0.02em',
      }}>
        Past the horizon,<br/>
        <span style={{ color: '#FFD78A' }}>only you.</span>
      </div>
      <div style={{
        fontSize: 14, color: '#898998', textAlign: 'center',
        marginTop: 18, lineHeight: 1.5, padding: '0 12px',
      }}>
        End-to-end encrypted messaging. Only the people you're talking to can read what you send.
      </div>

      <div style={{ flex: 1 }}/>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <Button variant="primary" size="lg" style={{ width: '100%' }}>Continue with phone</Button>
        <Button variant="ghost" size="lg" style={{ width: '100%', color: '#BDBDC9' }}>I already have an account</Button>
      </div>

      <div style={{
        display: 'flex', alignItems: 'center', gap: 6,
        justifyContent: 'center', marginTop: 24,
        fontSize: 11, color: '#54546A', letterSpacing: '0.04em',
      }}>
        <Icon name="lock" size={11} color="#A8C8FF"/> Encrypted from the first byte
      </div>
    </div>
  );
}

function MobileChatList({ chats, onOpen }) {
  return (
    <div style={{
      height: '100%', background: '#040408', color: '#F2EDE3',
      fontFamily: 'Geist, system-ui, sans-serif',
      display: 'flex', flexDirection: 'column',
    }}>
      <div style={{
        padding: '64px 18px 12px',
        display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between',
      }}>
        <div>
          <div style={{
            fontSize: 11, letterSpacing: '0.14em', textTransform: 'uppercase',
            color: '#898998', fontWeight: 500, marginBottom: 4,
            display: 'flex', alignItems: 'center', gap: 6,
          }}>
            <Icon name="lock" size={11} color="#A8C8FF"/> Powehi
          </div>
          <div style={{ fontSize: 28, fontWeight: 600, letterSpacing: '-0.02em' }}>Chats</div>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          <IconBtn icon="search" size={36}/>
          <IconBtn icon="plus" size={36} style={{ background: 'rgba(255,138,61,0.12)', color: '#FF9E52' }}/>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '4px 8px 16px' }}>
        {chats.map(c => (
          <div key={c.id} onClick={() => onOpen(c.id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 12,
              padding: '12px 12px', borderRadius: 14, cursor: 'pointer',
            }}>
            <Avatar name={c.name} size={48} online={c.online}/>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 15, fontWeight: 500 }}>{c.name}</span>
                <span style={{ fontSize: 11, color: '#898998', fontFamily: 'Geist Mono, monospace' }}>{c.time}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 3 }}>
                {c.typing ? (
                  <span style={{ fontSize: 13, color: '#FF9E52', fontStyle: 'italic' }}>typing…</span>
                ) : (
                  <span style={{
                    fontSize: 13, color: '#898998',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1,
                  }}>{c.last}</span>
                )}
                {c.unread > 0 && (
                  <span style={{
                    background: '#FF8A3D', color: '#2A0A00',
                    fontWeight: 600, fontSize: 10, borderRadius: 9999, padding: '2px 7px',
                  }}>{c.unread}</span>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div style={{
        height: 64, flex: 'none', borderTop: '1px solid rgba(242,237,227,0.06)',
        background: 'rgba(12,12,20,0.8)',
        backdropFilter: 'blur(20px)', WebkitBackdropFilter: 'blur(20px)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-around',
        padding: '0 24px 6px',
      }}>
        <TabIcon icon="chat" label="Chats" active/>
        <TabIcon icon="phone" label="Calls"/>
        <TabIcon icon="user" label="Contacts"/>
        <TabIcon icon="settings" label="Settings"/>
      </div>
    </div>
  );
}

function TabIcon({ icon, label, active }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2,
      color: active ? '#FF9E52' : '#898998',
    }}>
      <Icon name={icon} size={22}/>
      <span style={{ fontSize: 10, fontWeight: active ? 500 : 400 }}>{label}</span>
    </div>
  );
}

function MobileConversation({ chat, onBack }) {
  const ref = React.useRef(null);
  React.useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, []);
  return (
    <div style={{
      height: '100%', background: '#040408', color: '#F2EDE3',
      fontFamily: 'Geist, system-ui, sans-serif',
      display: 'flex', flexDirection: 'column',
    }}>
      <div style={{
        padding: '60px 12px 10px',
        display: 'flex', alignItems: 'center', gap: 8,
        borderBottom: '1px solid rgba(242,237,227,0.06)',
        background: 'rgba(4,4,8,0.9)',
        backdropFilter: 'blur(12px)', WebkitBackdropFilter: 'blur(12px)',
      }}>
        <button onClick={onBack} style={{
          width: 32, height: 32, background: 'transparent', border: 'none',
          color: '#FF9E52', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}><Icon name="arrowLeft" size={20}/></button>
        <Avatar name={chat.name} size={34} online={chat.online}/>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 14, fontWeight: 500 }}>{chat.name}</span>
            <Icon name="lock" size={10} color="#A8C8FF"/>
          </div>
          <div style={{ fontSize: 11, color: '#898998' }}>
            {chat.online ? 'online' : 'last seen 2h ago'}
          </div>
        </div>
        <IconBtn icon="phone" size={32}/>
        <IconBtn icon="video" size={32}/>
      </div>

      <div ref={ref} style={{
        flex: 1, overflowY: 'auto', padding: '16px 14px',
        display: 'flex', flexDirection: 'column', gap: 4,
        background: 'radial-gradient(ellipse 100% 60% at 50% 110%, rgba(255,138,61,0.07), transparent 60%), #040408',
      }}>
        <div style={{
          alignSelf: 'center', maxWidth: '90%', textAlign: 'center',
          padding: '10px 14px', margin: '4px 0 16px',
          background: 'rgba(168,200,255,0.05)',
          border: '1px solid rgba(168,200,255,0.2)',
          borderRadius: 10, fontSize: 11, color: '#C8DCFF', lineHeight: 1.5,
        }}>
          <Icon name="lock" size={11} style={{ verticalAlign: '-2px', marginRight: 4 }}/>
          Messages are end-to-end encrypted. Tap to verify {chat.name.split(' ')[0]}'s keys.
        </div>

        {chat.messages.map((m, i) => {
          if (m.day) return (
            <React.Fragment key={i}>
              <div style={{
                alignSelf: 'center', margin: '10px 0 6px',
                fontSize: 10, letterSpacing: '0.14em',
                textTransform: 'uppercase', color: '#54546A',
              }}>{m.day}</div>
              <MobileBubble msg={m}/>
            </React.Fragment>
          );
          return <MobileBubble key={i} msg={m}/>;
        })}
      </div>

      <div style={{ flex: 'none', padding: '8px 12px 12px', background: 'rgba(4,4,8,0.95)' }}>
        <div style={{
          background: '#0C0C14',
          border: '1px solid rgba(242,237,227,0.08)',
          borderRadius: 22, padding: '6px 6px 6px 14px',
          display: 'flex', alignItems: 'center', gap: 4,
        }}>
          <Icon name="attach" size={20} color="#898998"/>
          <input placeholder={`Message ${chat.name.split(' ')[0]}`}
            style={{
              flex: 1, background: 'transparent', border: 'none', outline: 'none',
              color: '#F2EDE3', fontFamily: 'Geist, system-ui, sans-serif',
              fontSize: 15, padding: '8px 6px',
            }}/>
          <button style={{
            width: 32, height: 32, borderRadius: '50%', border: 'none',
            background: 'linear-gradient(180deg, #FF9E52, #FF7A2B)',
            color: '#2A0A00',
            display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer',
            boxShadow: '0 0 0 1px rgba(255,138,61,0.35), 0 0 12px rgba(255,138,61,0.3)',
          }}><Icon name="mic" size={16}/></button>
        </div>
      </div>
    </div>
  );
}

function MobileBubble({ msg }) {
  const isMe = msg.from === 'me';
  return (
    <div style={{
      display: 'flex', justifyContent: isMe ? 'flex-end' : 'flex-start',
      marginTop: msg.continued ? 2 : 6,
    }}>
      <div style={{
        maxWidth: '78%', padding: '8px 13px',
        fontSize: 14, lineHeight: 1.4, borderRadius: 18,
        ...(isMe ? {
          background: 'linear-gradient(135deg, #FF9E52, #F26F1F)',
          color: '#2A1100',
          borderBottomRightRadius: msg.last ? 6 : 18,
          boxShadow: '0 0 18px rgba(255,138,61,0.18)',
        } : {
          background: '#16161F', color: '#F2EDE3',
          border: '1px solid rgba(242,237,227,0.04)',
          borderBottomLeftRadius: msg.last ? 6 : 18,
        }),
      }}>
        {msg.text}
        {msg.last && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            marginLeft: 8, opacity: 0.7,
            fontSize: 10, fontFamily: 'Geist Mono, monospace',
            verticalAlign: '2px',
          }}>
            {msg.time}
            {isMe && <Icon name="doublecheck" size={11} color={msg.read ? '#A8C8FF' : 'currentColor'}/>}
          </span>
        )}
      </div>
    </div>
  );
}

Object.assign(window, { MobileWelcome, MobileChatList, MobileConversation, MobileBubble, TabIcon });
