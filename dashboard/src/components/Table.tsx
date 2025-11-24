import { clsx } from 'clsx'

interface TableProps {
  children: React.ReactNode
  className?: string
}

export function Table({ children, className }: TableProps) {
  return (
    <div className={clsx('overflow-x-auto', className)}>
      <table className="min-w-full divide-y divide-gray-200">{children}</table>
    </div>
  )
}

export function TableHead({ children }: TableProps) {
  return <thead className="bg-gray-50">{children}</thead>
}

export function TableBody({ children }: TableProps) {
  return <tbody className="bg-white divide-y divide-gray-200">{children}</tbody>
}

export function TableRow({ children, className }: TableProps) {
  return <tr className={clsx('hover:bg-gray-50', className)}>{children}</tr>
}

interface TableCellProps extends TableProps {
  header?: boolean
  colSpan?: number
}

export function TableCell({ children, className, header, colSpan }: TableCellProps) {
  const Component = header ? 'th' : 'td'
  return (
    <Component
      colSpan={colSpan}
      className={clsx(
        'px-6 py-4 text-sm',
        header
          ? 'text-left font-medium text-gray-500 uppercase tracking-wider'
          : 'text-gray-900 whitespace-nowrap',
        className
      )}
    >
      {children}
    </Component>
  )
}
