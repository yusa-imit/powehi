// Powehi · Welcome / Onboarding

function Welcome({ onComplete }) {
  const [step, setStep] = React.useState('phone');
  const [phone, setPhone] = React.useState('+1 555 0124');
  const [code, setCode] = React.useState(['', '', '', '', '', '']);
  const codeRefs = React.useRef([]);

  const setDigit = (i, v) => {
    if (!/^\d?$/.test(v)) return;
    const next = [...code]; next[i] = v; setCode(next);
    if (v && i < 5) codeRefs.current[i + 1]?.focus();
  };

  return (
    <div style={{
      position: 'fixed', inset: 0,
      background: 'radial-gradient(ellipse 80% 60% at 50% 30%, rgba(255,138,61,0.18), transparent 60%), radial-gradient(ellipse 40% 30% at 50% 30%, rgba(168,200,255,0.08), transparent 70%), var(--bg-void)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 100,
    }}>
      <div style={{
        width: 420, padding: '40px 36px',
        background: 'rgba(12,12,20,0.6)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        border: '1px solid var(--border-soft)',
        borderRadius: 24,
        boxShadow: '0 24px 64px rgba(0,0,0,0.75), 0 8px 16px rgba(0,0,0,0.55)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 28 }}>
          <Logo size={72}/>
        </div>
        <div style={{
          fontFamily: 'var(--font-serif)', fontStyle: 'italic',
          fontSize: 36, color: 'var(--fg-1)', textAlign: 'center',
          lineHeight: 1.1, letterSpacing: '-0.02em',
        }}>
          {step === 'phone' && 'Past the horizon,'}
          {step === 'code' && 'We sent you a code.'}
          {step === 'phone' && <><br/><span style={{ color: '#FFD78A' }}>only you.</span></>}
        </div>
        <div style={{
          fontSize: 13, color: 'var(--fg-3)',
          textAlign: 'center', margin: '14px 0 28px', lineHeight: 1.5,
        }}>
          {step === 'phone' && 'Sign in with your number. We never see your messages.'}
          {step === 'code' && `Enter the 6-digit code we sent to ${phone}.`}
        </div>

        {step === 'phone' && (
          <>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 20 }}>
              <label style={{
                fontSize: 11, fontWeight: 500, letterSpacing: '0.14em',
                textTransform: 'uppercase', color: 'var(--fg-3)',
              }}>Phone number</label>
              <input value={phone} onChange={e => setPhone(e.target.value)}
                style={{
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-soft)',
                  color: 'var(--fg-1)', borderRadius: 12,
                  padding: '13px 16px', fontSize: 16,
                  fontFamily: 'var(--font-mono)', letterSpacing: '0.02em',
                  outline: 'none',
                  boxShadow: 'inset 0 1px 2px rgba(0,0,0,0.55)',
                }}
                onFocus={e => e.currentTarget.style.borderColor = 'rgba(255,138,61,0.5)'}
                onBlur={e => e.currentTarget.style.borderColor = 'var(--border-soft)'}/>
            </div>
            <Button variant="primary" size="lg" style={{ width: '100%' }} onClick={() => setStep('code')}>
              Send code
            </Button>
          </>
        )}

        {step === 'code' && (
          <>
            <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginBottom: 24 }}>
              {code.map((d, i) => (
                <input key={i} ref={el => codeRefs.current[i] = el}
                  value={d} onChange={e => setDigit(i, e.target.value)} maxLength={1}
                  style={{
                    width: 44, height: 54, textAlign: 'center',
                    background: 'var(--bg-input)',
                    border: `1px solid ${d ? 'rgba(255,138,61,0.5)' : 'var(--border-soft)'}`,
                    color: 'var(--fg-1)', borderRadius: 10,
                    fontFamily: 'var(--font-mono)', fontSize: 22, fontWeight: 500,
                    outline: 'none',
                    boxShadow: d ? '0 0 0 3px rgba(255,138,61,0.15)' : 'inset 0 1px 2px rgba(0,0,0,0.55)',
                    transition: 'all 200ms',
                  }}/>
              ))}
            </div>
            <Button variant="primary" size="lg" style={{ width: '100%' }}
              disabled={code.some(d => !d)}
              onClick={onComplete}>
              Continue
            </Button>
            <button onClick={() => setStep('phone')}
              style={{
                width: '100%', marginTop: 12,
                background: 'transparent', border: 'none',
                color: 'var(--fg-3)', fontSize: 12,
                fontFamily: 'var(--font-sans)', cursor: 'pointer',
              }}>← Use a different number</button>
          </>
        )}

        <div style={{
          marginTop: 28, paddingTop: 18,
          borderTop: '1px solid var(--border-faint)',
          fontSize: 11, color: 'var(--fg-4)', textAlign: 'center',
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
        }}>
          <Icon name="lock" size={11} color="#A8C8FF"/>
          <span style={{ letterSpacing: '0.04em' }}>End-to-end encrypted from the first byte</span>
        </div>
      </div>
    </div>
  );
}

window.Welcome = Welcome;
