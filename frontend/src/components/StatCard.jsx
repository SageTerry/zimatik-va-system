import Card from './Card'

export default function StatCard({ label, value, icon: Icon, accentClassName = 'text-ink' }) {
  return (
    <Card className="relative">
      {Icon && (
        <span className="absolute right-5 top-5 flex h-10 w-10 items-center justify-center rounded-full bg-brand-light text-brand">
          <Icon size={20} strokeWidth={2} />
        </span>
      )}
      <p className="font-body text-label uppercase tracking-wide text-ink-3">{label}</p>
      <p className={`mt-2 font-display text-stat ${accentClassName}`}>{value}</p>
    </Card>
  )
}
