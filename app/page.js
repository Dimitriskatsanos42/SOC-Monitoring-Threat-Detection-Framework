import Link from 'next/link';

const metrics = [
  { label: 'Active alerts', value: '24', tone: 'danger' },
  { label: 'Critical hosts', value: '6', tone: 'warning' },
  { label: 'Healthy agents', value: '12', tone: 'success' },
  { label: 'Detection rules', value: '18', tone: 'accent' }
];

export default function HomePage() {
  return (
    <main className="shell">
      <section className="hero">
        <div>
          <p className="eyebrow">Next.js SOC console</p>
          <h1>Modern security operations experience</h1>
          <p>This shell is ready to connect to the existing FastAPI backend and scale into a richer React/Next.js product.</p>
        </div>
        <div className="hero-actions">
          <Link href="/dashboard" className="button">Open dashboard</Link>
          <span className="helper">FastAPI + Next.js + React architecture</span>
        </div>
      </section>

      <section className="grid">
        {metrics.map((metric) => (
          <article key={metric.label} className={`metric-card ${metric.tone}`}>
            <div className="metric-label">{metric.label}</div>
            <div className="metric-value">{metric.value}</div>
          </article>
        ))}
      </section>
    </main>
  );
}
