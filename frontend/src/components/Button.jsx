const VARIANT_STYLES = {
  primary: 'bg-ink text-surface border-ink hover:bg-ink-2',
  secondary: 'bg-transparent text-ink border-line-strong hover:bg-sunken',
  ghost: 'bg-transparent text-ink-2 border-transparent hover:text-ink hover:bg-sunken/60',
  small: 'bg-transparent text-ink border-line-strong hover:bg-sunken',
}

const SIZE_STYLES = {
  primary: 'px-5 py-2.5 text-base radius-a',
  secondary: 'px-5 py-2.5 text-base radius-b',
  ghost: 'px-3 py-2 text-base radius-b',
  small: 'px-3 py-1.5 text-sm radius-c',
}

export default function Button({ variant = 'primary', className = '', children, ...props }) {
  const variantKey = VARIANT_STYLES[variant] ? variant : 'primary'
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 border font-body font-normal transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${SIZE_STYLES[variantKey]} ${VARIANT_STYLES[variantKey]} ${className}`}
      {...props}
    >
      {children}
    </button>
  )
}
