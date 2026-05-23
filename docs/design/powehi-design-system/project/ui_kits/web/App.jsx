// Powehi · Main app

const SEED_CHATS = [
  {
    id: 'maya', name: 'Maya Akana', handle: 'maya', online: true,
    last: 'Bringing the notebook.', time: '14:32', unread: 0,
    verifiedAgo: '2 days ago',
    messages: [
      { day: 'Yesterday', from: 'them', text: 'Hey — are you free tomorrow morning?' },
      { from: 'me', text: 'Should be. What time?', continued: true, last: true, time: '20:14', read: true },
      { day: 'Today', from: 'them', text: '9am at the corner café?' },
      { from: 'them', text: 'I have a thing at 10:30 so let\'s keep it short ✺', continued: true, last: true, time: '14:30' },
      { from: 'me', text: 'Works for me.' },
      { from: 'me', text: 'Bringing the notebook.', continued: true, last: true, time: '14:32', read: true },
    ],
  },
  {
    id: 'jordan', name: 'Jordan', handle: 'jordan_b', online: false, lastSeen: '2h ago',
    last: '📎 receipt.pdf', time: '12:08', unread: 2,
    messages: [
      { day: 'Today', from: 'them', text: 'split for last night' },
      { from: 'them', text: '📎 receipt.pdf', continued: true, last: true, time: '12:08' },
    ],
  },
  {
    id: 'ari', name: 'Ari Work', handle: 'ari', online: false, lastSeen: 'yesterday',
    last: 'You: see you tmrw', time: 'Yesterday', unread: 0,
    messages: [
      { day: 'Yesterday', from: 'them', text: 'tomorrow 10am for the review?' },
      { from: 'me', text: 'see you tmrw', continued: true, last: true, time: '17:42', read: true },
    ],
  },
  {
    id: 'family', name: 'Family', handle: 'family_4', online: false, lastSeen: '3h ago',
    last: 'Mom: love you all 🌒', time: '11:14', unread: 0,
    messages: [
      { day: 'Today', from: 'them', text: 'love you all 🌒' },
      { from: 'them', text: '— Mom', continued: true, last: true, time: '11:14' },
    ],
  },
  {
    id: 'sam', name: 'Sam', handle: 'sam.k', online: true, typing: true,
    last: 'typing…', time: '14:33', unread: 0,
    messages: [
      { day: 'Today', from: 'me', text: 'did the deploy go through?', last: true, time: '14:31', read: true },
    ],
  },
  {
    id: 'nia', name: 'Nia Oduya', handle: 'nia', online: false, lastSeen: 'mon',
    last: 'sure, send it over', time: 'Mon', unread: 0,
    messages: [
      { day: 'Monday', from: 'them', text: 'sure, send it over', last: true, time: '09:12' },
    ],
  },
];

function App() {
  const [welcomed, setWelcomed] = React.useState(false);
  const [chats, setChats] = React.useState(SEED_CHATS);
  const [activeId, setActiveId] = React.useState('maya');
  const [search, setSearch] = React.useState('');
  const [infoOpen, setInfoOpen] = React.useState(false);
  const active = chats.find(c => c.id === activeId);

  const sendMessage = (text) => {
    const now = new Date();
    const time = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
    setChats(cs => cs.map(c => {
      if (c.id !== activeId) return c;
      const msgs = [...c.messages];
      for (let i = msgs.length - 1; i >= 0; i--) {
        if (msgs[i].from === 'me' && msgs[i].last) {
          msgs[i] = { ...msgs[i], last: false, continued: true };
          break;
        }
      }
      msgs.push({ from: 'me', text, last: true, time, read: false,
        continued: msgs.length > 0 && msgs[msgs.length - 1].from === 'me' });
      return { ...c, messages: msgs, last: text, time };
    }));
  };

  if (!welcomed) return <Welcome onComplete={() => setWelcomed(true)}/>;

  return (
    <div style={{
      height: '100vh', width: '100vw',
      display: 'flex',
      background: 'var(--bg-void)',
      color: 'var(--fg-1)',
      fontFamily: 'var(--font-sans)',
      overflow: 'hidden',
    }}>
      <Sidebar chats={chats} activeId={activeId}
        onSelect={setActiveId}
        onNewChat={() => alert('New chat — not wired')}
        onSettings={() => alert('Settings — not wired')}
        onSearch={setSearch} searchQuery={search}/>

      {active && (
        <main style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
          <ConversationHeader chat={active}
            onCall={() => alert('Voice call')}
            onVideo={() => alert('Video call')}
            onInfo={() => setInfoOpen(v => !v)}
            infoOpen={infoOpen}/>
          <MessageList messages={active.messages} partner={active.name}/>
          <Composer onSend={sendMessage} partner={active.name}/>
        </main>
      )}

      {infoOpen && active && <InfoPanel chat={active} onClose={() => setInfoOpen(false)}/>}
    </div>
  );
}

window.App = App;
