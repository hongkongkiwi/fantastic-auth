import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DataTable, createSelectColumn } from '../../components/DataTable'
import type { ColumnDef } from '@tanstack/react-table'

interface TestData {
  id: string
  name: string
  email: string
  status: 'active' | 'inactive'
}

const testData: TestData[] = [
  { id: '1', name: 'John Doe', email: 'john@example.com', status: 'active' },
  { id: '2', name: 'Jane Smith', email: 'jane@example.com', status: 'active' },
  { id: '3', name: 'Bob Wilson', email: 'bob@example.com', status: 'inactive' },
]

const columns: ColumnDef<TestData>[] = [
  createSelectColumn<TestData>(),
  {
    accessorKey: 'name',
    header: 'Name',
  },
  {
    accessorKey: 'email',
    header: 'Email',
  },
  {
    accessorKey: 'status',
    header: 'Status',
  },
]

describe('DataTable Integration', () => {
  it('renders data correctly', () => {
    render(<DataTable columns={columns} data={testData} />)
    
    expect(screen.getByText('John Doe')).toBeInTheDocument()
    expect(screen.getByText('jane@example.com')).toBeInTheDocument()
    expect(screen.getByText('inactive')).toBeInTheDocument()
  })

  it('filters data based on search', async () => {
    const user = userEvent.setup()
    
    render(<DataTable columns={columns} data={testData} />)
    
    const searchInput = screen.getByPlaceholderText('Search…')
    await user.type(searchInput, 'Jane')
    
    expect(screen.getByText('Jane Smith')).toBeInTheDocument()
    expect(screen.queryByText('John Doe')).not.toBeInTheDocument()
  })

  it('selects rows with checkboxes', async () => {
    const user = userEvent.setup()
    const handleSelectionChange = vi.fn()
    
    render(
      <DataTable
        columns={columns}
        data={testData}
        getRowId={(row) => row.id}
        onSelectionChange={handleSelectionChange}
      />
    )
    
    const checkboxes = screen.getAllByRole('checkbox')
    await user.click(checkboxes[1])
    
    expect(handleSelectionChange).toHaveBeenCalledWith(['1'])
  })

  it('handles pagination', async () => {
    const user = userEvent.setup()
    
    render(<DataTable columns={columns} data={testData} pageSize={2} />)
    
    expect(screen.getByText(/Page 1 of 2/)).toBeInTheDocument()
    
    const nextButton = screen.getByLabelText('Next page')
    await user.click(nextButton)

    await waitFor(() => {
      expect(screen.getByText(/Page 2 of 2/)).toBeInTheDocument()
    })
  })

  it('calls onRowClick when row is clicked', async () => {
    const user = userEvent.setup()
    const handleRowClick = vi.fn()
    
    render(
      <DataTable
        columns={columns}
        data={testData}
        onRowClick={handleRowClick}
      />
    )
    
    const johnRow = screen.getByText('John Doe').closest('tr')
    if (johnRow) {
      await user.click(johnRow)
    }
    
    expect(handleRowClick).toHaveBeenCalledWith(testData[0])
  })
})
