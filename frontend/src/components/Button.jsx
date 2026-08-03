const VARIANT_STYLES = {
  primary: 'bg-brand text-white border-brand shadow-sm hover:bg-brand-dark hover:border-brand-dark',
  secondary: 'bg-surface text-ink border-line-strong hover:bg-sunken',
  ghost: 'bg-transparent text-ink-2 border-transparent hover:text-ink hover:bg-sunken',
  small: 'bg-surface text-ink border-line-strong hover:bg-sunken',
}

const SIZE_STYLES = {
  primary: 'px-5 py-2.5 text-sm font-semibold radius-b',
  secondary: 'px-5 py-2.5 text-sm font-semibold radius-b',
  ghost: 'px-3 py-2 text-sm font-semibold radius-b',
  small: 'px-3 py-1.5 text-xs font-semibold radius-c',
}

export default function Button({ variant = 'primary', className = '', children, ...props }) {
  const variantKey = VARIANT_STYLES[variant] ? variant : 'primary'
  return (
    <button
      className={`inline-flex cursor-pointer items-center justify-center gap-2 border font-body transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50 ${SIZE_STYLES[variantKey]} ${VARIANT_STYLES[variantKey]} ${className}`}
      {...props}
    >
      {children}
    </button>
  )
}
