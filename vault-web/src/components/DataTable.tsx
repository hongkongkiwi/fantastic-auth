import * as React from 'react'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  flexRender,
  type ColumnDef,
  type SortingState,
  type ColumnFiltersState,
  type VisibilityState,
} from '@tanstack/react-table'
import { useVirtualizer } from '@tanstack/react-virtual'
import {
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Search,
  Download,
  Filter,
  ArrowUpDown,
  MoreHorizontal,
  X,
} from 'lucide-react'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import { cn } from '../lib/utils'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Badge } from './ui/Badge'
import { Skeleton } from './ui/Skeleton'
import { Checkbox } from './ui/Checkbox'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from './ui/DropdownMenu'

export interface BulkAction<TData> {
  id: string
  label: string
  icon?: React.ReactNode
  variant?: 'default' | 'destructive'
  onClick: (selectedRows: TData[]) => void
  disabled?: boolean
}

interface DataTableProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[]
  data: TData[]
  isLoading?: boolean
  searchable?: boolean
  searchPlaceholder?: string
  pagination?: boolean
  pageSize?: number
  pageSizeOptions?: number[]
  onRowClick?: (row: TData) => void
  selectedRows?: string[]
  onSelectionChange?: (selectedIds: string[]) => void
  getRowId?: (row: TData) => string
  emptyState?: React.ReactNode
  toolbar?: React.ReactNode
  exportable?: boolean
  exportFileName?: string
  bulkActions?: BulkAction<TData>[]
  enableRowSelection?: boolean
}

export function DataTable<TData, TValue>({
  columns,
  data,
  isLoading,
  searchable = true,
  searchPlaceholder = 'Search…',
  pagination = true,
  pageSize = 10,
  pageSizeOptions = [5, 10, 20, 50, 100],
  onRowClick,
  selectedRows,
  onSelectionChange,
  getRowId,
  emptyState,
  toolbar,
  exportable = true,
  exportFileName = 'export',
  bulkActions,
  enableRowSelection = true,
}: DataTableProps<TData, TValue>) {
  const [sorting, setSorting] = React.useState<SortingState>([])
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([])
  const [globalFilter, setGlobalFilter] = React.useState('')
  const [searchValue, setSearchValue] = React.useState('')
  const deferredSearch = React.useDeferredValue(searchValue)
  const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>({})
  const [rowSelection, setRowSelection] = React.useState<Record<string, boolean>>({})
  const [paginationState, setPaginationState] = React.useState({
    pageIndex: 0,
    pageSize,
  })
  const prefersReducedMotion = useReducedMotion()

  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onGlobalFilterChange: setGlobalFilter,
    onColumnVisibilityChange: setColumnVisibility,
    onRowSelectionChange: setRowSelection,
    enableRowSelection,
    getRowId,
    state: {
      sorting,
      columnFilters,
      globalFilter,
      columnVisibility,
      rowSelection,
      pagination: paginationState,
    },
    onPaginationChange: setPaginationState,
  })

  React.useEffect(() => {
    setPaginationState((prev) => ({
      pageIndex: 0,
      pageSize,
    }))
  }, [pageSize])

  React.useEffect(() => {
    setGlobalFilter(deferredSearch)
  }, [deferredSearch])

  const tableContainerRef = React.useRef<HTMLDivElement | null>(null)
  const rows = table.getRowModel().rows
  const shouldVirtualize = rows.length > 50
  const rowVirtualizer = useVirtualizer({
    count: shouldVirtualize ? rows.length : 0,
    getScrollElement: () => tableContainerRef.current,
    estimateSize: () => 56,
    overscan: 8,
  })
  const virtualRows = rowVirtualizer.getVirtualItems()
  const paddingTop =
    shouldVirtualize && virtualRows.length > 0 ? virtualRows[0].start : 0
  const paddingBottom =
    shouldVirtualize && virtualRows.length > 0
      ? rowVirtualizer.getTotalSize() -
        virtualRows[virtualRows.length - 1].end
      : 0

  // Update parent when selection changes
  React.useEffect(() => {
    if (onSelectionChange) {
      const selectedIds = Object.keys(rowSelection).filter((id) => rowSelection[id])
      onSelectionChange(selectedIds)
    }
  }, [rowSelection, onSelectionChange])

  // Sync external selection state
  React.useEffect(() => {
    if (selectedRows) {
      const selection: Record<string, boolean> = {}
      selectedRows.forEach((id) => {
        selection[id] = true
      })
      setRowSelection(selection)
    }
  }, [selectedRows])

  const handleExport = () => {
    const rows = table.getFilteredRowModel().rows
    const headers = columns
      .filter((col) => col.id !== 'select' && col.id !== 'actions')
      .map((col) => col.header as string)

    const csvContent = [
      headers.join(','),
      ...rows.map((row) =>
        columns
          .filter((col) => col.id !== 'select' && col.id !== 'actions')
          .map((col) => {
            const value = row.getValue(col.id as string)
            const stringValue = String(value ?? '')
            return `"${stringValue.replace(/"/g, '""')}"`
          })
          .join(',')
      ),
    ].join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${exportFileName}_${new Date().toISOString().split('T')[0]}.csv`
    link.click()
    URL.revokeObjectURL(url)
  }

  const selectedCount = Object.keys(rowSelection).filter((id) => rowSelection[id]).length

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2 flex-1">
          {searchable && (
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" aria-hidden="true" />
              <Input
                placeholder={searchPlaceholder}
                value={searchValue}
                onChange={(e) => setSearchValue(e.target.value)}
                className="pl-10"
                aria-label={searchPlaceholder}
                name="table-search"
                autoComplete="off"
              />
            </div>
          )}
          {toolbar}
        </div>

        <div className="flex items-center gap-2">
          {selectedCount > 0 && (
            <Badge variant="secondary">
              {selectedCount} selected
            </Badge>
          )}

          {exportable && (
            <Button
              variant="outline"
              size="sm"
              leftIcon={<Download className="h-4 w-4" />}
              onClick={handleExport}
            >
              Export
            </Button>
          )}

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" leftIcon={<Filter className="h-4 w-4" />}>
                Columns
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              {table
                .getAllColumns()
                .filter((column) => column.getCanHide())
                .map((column) => {
                  return (
                    <DropdownMenuCheckboxItem
                      key={column.id}
                      className="capitalize"
                      checked={column.getIsVisible()}
                      onCheckedChange={(value) => column.toggleVisibility(!!value)}
                    >
                      {column.id}
                    </DropdownMenuCheckboxItem>
                  )
                })}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Bulk Actions Bar */}
      <AnimatePresence>
        {selectedCount > 0 && bulkActions && bulkActions.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="flex items-center justify-between p-3 bg-primary/5 border rounded-lg"
          >
            <div className="flex items-center gap-3">
              <Checkbox
                checked={table.getIsAllPageRowsSelected()}
                indeterminate={table.getIsSomePageRowsSelected()}
                onCheckedChange={(checked) => table.toggleAllPageRowsSelected(!!checked)}
                label={`${selectedCount} selected`}
              />
              <Button
                variant="ghost"
                size="sm"
                onClick={() => table.toggleAllRowsSelected(false)}
              >
                <X className="h-4 w-4 mr-1" />
                Clear
              </Button>
            </div>
            <div className="flex items-center gap-2">
              {bulkActions.length <= 2 ? (
                bulkActions.map((action) => (
                  <Button
                    key={action.id}
                    variant={action.variant === 'destructive' ? 'destructive' : 'outline'}
                    size="sm"
                    leftIcon={action.icon}
                    onClick={() => {
                      const selectedData = table
                        .getSelectedRowModel()
                        .rows.map((row) => row.original)
                      action.onClick(selectedData)
                    }}
                    disabled={action.disabled}
                  >
                    {action.label}
                  </Button>
                ))
              ) : (
                <>
                  {bulkActions.slice(0, 1).map((action) => (
                    <Button
                      key={action.id}
                      variant={action.variant === 'destructive' ? 'destructive' : 'outline'}
                      size="sm"
                      leftIcon={action.icon}
                      onClick={() => {
                        const selectedData = table
                          .getSelectedRowModel()
                          .rows.map((row) => row.original)
                        action.onClick(selectedData)
                      }}
                      disabled={action.disabled}
                    >
                      {action.label}
                    </Button>
                  ))}
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="sm" leftIcon={<MoreHorizontal className="h-4 w-4" />}>
                        More Actions
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      {bulkActions.slice(1).map((action, index) => (
                        <React.Fragment key={action.id}>
                          {index > 0 && <DropdownMenuSeparator />}
                          <DropdownMenuItem
                            onClick={() => {
                              const selectedData = table
                                .getSelectedRowModel()
                                .rows.map((row) => row.original)
                              action.onClick(selectedData)
                            }}
                            disabled={action.disabled}
                            className={action.variant === 'destructive' ? 'text-destructive' : ''}
                          >
                            {action.icon && <span className="mr-2">{action.icon}</span>}
                            {action.label}
                          </DropdownMenuItem>
                        </React.Fragment>
                      ))}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Table */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div ref={tableContainerRef} className="max-h-[560px] overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <th
                      key={header.id}
                      className={cn(
                        'px-4 py-3 text-left font-medium text-muted-foreground'
                      )}
                    >
                      <div className="flex items-center gap-2">
                        {header.isPlaceholder ? null : header.column.getCanSort() ? (
                          <button
                            type="button"
                            className="inline-flex items-center gap-2 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                            onClick={header.column.getToggleSortingHandler()}
                            aria-label={`Sort by ${String(
                              header.column.columnDef.header ?? header.id
                            )}`}
                          >
                            {flexRender(
                              header.column.columnDef.header,
                              header.getContext()
                            )}
                            <span className="text-muted-foreground/50">
                              {header.column.getIsSorted() === 'asc' ? (
                                <ChevronUp className="h-4 w-4" aria-hidden="true" />
                              ) : header.column.getIsSorted() === 'desc' ? (
                                <ChevronDown className="h-4 w-4" aria-hidden="true" />
                              ) : (
                                <ArrowUpDown className="h-3 w-3" aria-hidden="true" />
                              )}
                            </span>
                          </button>
                        ) : (
                          flexRender(
                            header.column.columnDef.header,
                            header.getContext()
                          )
                        )}
                      </div>
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y">
              {isLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="border-b">
                    {columns.map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <Skeleton className="h-4 w-full" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : rows.length ? (
                <>
                  {shouldVirtualize ? (
                    <>
                      {paddingTop > 0 && (
                        <tr>
                          <td style={{ height: paddingTop }} colSpan={columns.length} />
                        </tr>
                      )}
                      {virtualRows.map((virtualRow, index) => {
                        const row = rows[virtualRow.index]
                        return (
                          <motion.tr
                            key={row.id}
                            initial={prefersReducedMotion ? false : { opacity: 0 }}
                            animate={{ opacity: 1 }}
                            className={cn(
                              'transition-colors',
                              onRowClick && 'cursor-pointer hover:bg-muted/50',
                              row.getIsSelected() && 'bg-primary/5'
                            )}
                            onClick={() => onRowClick?.(row.original)}
                            onKeyDown={(event) => {
                              if (!onRowClick) return
                              if (event.key === 'Enter' || event.key === ' ') {
                                event.preventDefault()
                                onRowClick(row.original)
                              }
                            }}
                            role={onRowClick ? 'button' : undefined}
                            tabIndex={onRowClick ? 0 : undefined}
                            transition={
                              prefersReducedMotion ? { duration: 0 } : { delay: index * 0.02 }
                            }
                          >
                            {row.getVisibleCells().map((cell) => (
                              <td key={cell.id} className="px-4 py-3">
                                {flexRender(cell.column.columnDef.cell, cell.getContext())}
                              </td>
                            ))}
                          </motion.tr>
                        )
                      })}
                      {paddingBottom > 0 && (
                        <tr>
                          <td style={{ height: paddingBottom }} colSpan={columns.length} />
                        </tr>
                      )}
                    </>
                  ) : (
                    rows.map((row, index) => (
                      <motion.tr
                        key={row.id}
                        initial={prefersReducedMotion ? false : { opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className={cn(
                          'transition-colors',
                          onRowClick && 'cursor-pointer hover:bg-muted/50',
                          row.getIsSelected() && 'bg-primary/5'
                        )}
                        onClick={() => onRowClick?.(row.original)}
                        onKeyDown={(event) => {
                          if (!onRowClick) return
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault()
                            onRowClick(row.original)
                          }
                        }}
                        role={onRowClick ? 'button' : undefined}
                        tabIndex={onRowClick ? 0 : undefined}
                        transition={
                          prefersReducedMotion ? { duration: 0 } : { delay: index * 0.02 }
                        }
                      >
                        {row.getVisibleCells().map((cell) => (
                          <td key={cell.id} className="px-4 py-3">
                            {flexRender(cell.column.columnDef.cell, cell.getContext())}
                          </td>
                        ))}
                      </motion.tr>
                    ))
                  )}
                </>
              ) : (
                <tr>
                  <td
                    colSpan={columns.length}
                    className="px-4 py-12 text-center text-muted-foreground"
                  >
                    {emptyState || (
                      <div className="flex flex-col items-center gap-2">
                        <Search className="h-8 w-8 text-muted-foreground/50" />
                        <p>No results found</p>
                      </div>
                    )}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {pagination && (
          <div className="flex items-center justify-between px-4 py-3 border-t bg-muted/30">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <span>
                Page {table.getState().pagination.pageIndex + 1} of{' '}
                {table.getPageCount()}
              </span>
              <span className="hidden sm:inline">
                ({table.getFilteredRowModel().rows.length} total)
              </span>
            </div>

            <div className="flex items-center gap-2">
              <select
                value={table.getState().pagination.pageSize}
                onChange={(e) => table.setPageSize(Number(e.target.value))}
                className="h-8 rounded-md border border-input bg-background px-2 text-sm"
                aria-label="Rows per page"
              >
                {pageSizeOptions.map((size) => (
                  <option key={size} value={size}>
                    {size} / page
                  </option>
                ))}
              </select>

              <div className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="icon-sm"
                  onClick={() => table.setPageIndex(0)}
                  disabled={!table.getCanPreviousPage()}
                  aria-label="First page"
                >
                  <ChevronsLeft className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="icon-sm"
                  onClick={() => table.previousPage()}
                  disabled={!table.getCanPreviousPage()}
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="icon-sm"
                  onClick={() => table.nextPage()}
                  disabled={!table.getCanNextPage()}
                  aria-label="Next page"
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="icon-sm"
                  onClick={() => table.setPageIndex(table.getPageCount() - 1)}
                  disabled={!table.getCanNextPage()}
                  aria-label="Last page"
                >
                  <ChevronsRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// Checkbox column helper
export function createSelectColumn<TData>(): ColumnDef<TData> {
  return {
    id: 'select',
    header: ({ table }) => (
      <div className="flex justify-center">
        <Checkbox
          checked={table.getIsAllPageRowsSelected()}
          indeterminate={table.getIsSomePageRowsSelected()}
          onCheckedChange={(checked) => table.toggleAllPageRowsSelected(!!checked)}
        />
      </div>
    ),
    cell: ({ row }) => (
      <div className="flex justify-center" onClick={(e) => e.stopPropagation()}>
        <Checkbox
          checked={row.getIsSelected()}
          onCheckedChange={(checked) => row.toggleSelected(!!checked)}
        />
      </div>
    ),
    enableSorting: false,
    enableHiding: false,
    size: 40,
  }
}

// Status badge cell helper
export function createStatusBadge(statusMap: Record<string, { label: string; variant: 'default' | 'success' | 'warning' | 'destructive' | 'info' }>) {
  return ({ getValue }: { getValue: () => unknown }) => {
    const status = String(getValue() ?? 'unknown')
    const config = statusMap[status] || { label: status, variant: 'default' }
    return <Badge variant={config.variant}>{config.label}</Badge>
  }
}

// Date cell helper
export function createDateCell() {
  return ({ getValue }: { getValue: () => unknown }) => {
    const value = getValue()
    if (!value) return <span className="text-muted-foreground">—</span>
    const date = value instanceof Date ? value : new Date(String(value))
    if (Number.isNaN(date.getTime())) {
      return <span className="text-muted-foreground">—</span>
    }
    return (
      <span className="text-muted-foreground">
        {new Intl.DateTimeFormat('en-US', {
          month: 'short',
          day: 'numeric',
          year: 'numeric',
        }).format(date)}
      </span>
    )
  }
}
