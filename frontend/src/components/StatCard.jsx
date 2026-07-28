import Card from './Card'

export default function StatCard({ label, value, icon: Icon, accentClassName = 'text-ink' }) {
  return (
    <Card className="relative">
      {Icon && (
        <span className="absolute right-4 top-4 text-ink-3">
          <Icon size={26} strokeWidth={2} />
        </span>
      )}
      <p className="font-body text-label uppercase tracking-wide text-ink-2">{label}</p>
      <p className={`mt-2 font-display text-stat ${accentClassName}`}>{value}</p>
    </Card>
  )
}
