export default function Card({ as: Tag = 'div', className = '', children, ...props }) {
  return (
    <Tag className={`radius-a border border-line bg-surface p-5 shadow-card ${className}`} {...props}>
      {children}
    </Tag>
  )
}
