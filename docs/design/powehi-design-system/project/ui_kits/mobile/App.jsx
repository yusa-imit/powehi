// Powehi · Mobile demo — three devices showing the flow

const MOBILE_CHATS = [
  { id: 'maya', name: 'Maya Akana', online: true, last: 'Bringing the notebook.', time: '14:32', unread: 0,
    messages: [
      { day: 'Yesterday' },
      { from: 'them', text: 'are you free tomorrow morning?' },
      { from: 'me', text: 'Should be — what time?', last: true, time: '20:14', read: true },
      { day: 'Today' },
      { from: 'them', text: '9am at the corner café?' },
      { from: 'them', text: 'I have a thing at 10:30 — keep it short ✺', continued: true, last: true, time: '14:30' },
      { from: 'me', text: 'Works.' },
      { from: 'me', text: 'Bringing the notebook.', continued: true, last: true, time: '14:32', read: true },
    ],
  },
  { id: 'jordan', name: 'Jordan', online: false, last: '📎 receipt.pdf', time: '12:08', unread: 2 },
  { id: 'sam', name: 'Sam', online: true, typing: true, last: 'typing…', time: 'now', unread: 0 },
  { id: 'family', name: 'Family', online: false, last: 'Mom: love you all 🌒', time: '11:14', unread: 0 },
  { id: 'ari', name: 'Ari Work', online: false, last: 'You: see you tmrw', time: 'Yesterday', unread: 0 },
  { id: 'nia', name: 'Nia Oduya', online: false, last: 'sure, send it over', time: 'Mon', unread: 0 },
];

function MobileDemo() {
  return (
    <div style={{
      minHeight: '100vh',
      background: 'radial-gradient(ellipse 60% 40% at 50% 20%, rgba(255,138,61,0.08), transparent 60%), #040408',
      padding: '40px 24px 60px',
      fontFamily: 'Geist, system-ui, sans-serif',
      color: '#F2EDE3',
    }}>
      <div style={{ textAlign: 'center', marginBottom: 40 }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
          <Logo size={32}/>
          <span style={{ fontWeight: 600, fontSize: 22, letterSpacing: '-0.03em' }}>powehi</span>
        </div>
        <div style={{ fontSize: 13, color: '#898998', letterSpacing: '0.04em' }}>
          Mobile UI kit · iOS device frame · 390×844
        </div>
      </div>

      <div style={{
        display: 'flex', gap: 40, justifyContent: 'center', flexWrap: 'wrap',
        alignItems: 'flex-start',
      }}>
        <ScreenCard label="Welcome">
          <IOSDevice dark={true} width={390} height={844}><MobileWelcome/></IOSDevice>
        </ScreenCard>
        <ScreenCard label="Chat list">
          <IOSDevice dark={true} width={390} height={844}>
            <MobileChatList chats={MOBILE_CHATS} onOpen={() => {}}/>
          </IOSDevice>
        </ScreenCard>
        <ScreenCard label="Conversation">
          <IOSDevice dark={true} width={390} height={844}>
            <MobileConversation chat={MOBILE_CHATS[0]} onBack={() => {}}/>
          </IOSDevice>
        </ScreenCard>
      </div>

      <div style={{ textAlign: 'center', marginTop: 32, fontSize: 11, color: '#54546A', letterSpacing: '0.04em' }}>
        Static screens — for an interactive walkthrough, see the web kit.
      </div>
    </div>
  );
}

window.MobileDemo = MobileDemo;
