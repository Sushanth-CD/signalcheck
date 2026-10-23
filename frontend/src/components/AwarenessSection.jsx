const topics = [
  {
    number: "01",
    title: "Phishing & deceptive links",
    text: "Unexpected urgency, requests for passwords or one-time codes, and links that hide their destination deserve a pause. Verify through an official app or a web address you enter yourself.",
    tip: "Never share an OTP, PIN, or password with someone who contacts you unexpectedly.",
  },
  {
    number: "02",
    title: "Digital arrest scams",
    text: "Scammers may impersonate police or government officials, threaten arrest, or insist you stay on a call. Indian law enforcement does not place people under remote ‘digital arrest’.",
    tip: "End suspicious calls, speak with someone you trust, and verify claims using independently sourced contacts.",
  },
  {
    number: "03",
    title: "Apps & sensitive permissions",
    text: "SMS and accessibility access can expose sensitive activity when misused. An app asking for powerful permissions should have a clear, relevant reason.",
    tip: "Install from trusted sources and review permissions before granting them. This tool does not inspect APK files.",
  },
];

export default function AwarenessSection() {
  return (
    <section className="awareness-section" aria-labelledby="awareness-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Build safer habits</p>
          <h2 id="awareness-title">A little awareness goes a long way</h2>
        </div>
        <p>General guidance, separate from the findings above.</p>
      </div>
      <div className="awareness-grid">
        {topics.map((topic) => (
          <article className="awareness-card" key={topic.number}>
            <span className="topic-number">{topic.number}</span>
            <h3>{topic.title}</h3>
            <p>{topic.text}</p>
            <div className="topic-tip"><span aria-hidden="true">↳</span>{topic.tip}</div>
          </article>
        ))}
      </div>
    </section>
  );
}
