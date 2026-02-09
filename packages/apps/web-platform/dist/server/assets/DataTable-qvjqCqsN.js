import { jsxs, jsx } from "react/jsx-runtime";
import { useState, useEffect, useCallback } from "react";
import { useReactTable, getPaginationRowModel, getSortedRowModel, getFilteredRowModel, getCoreRowModel, flexRender } from "@tanstack/react-table";
import { I as Input } from "./Input-D8nMsmC2.js";
import { c as cn, B as Button, a as Badge, l as formatDate } from "./router-BqFKwE1w.js";
function DataTable({
  columns,
  data,
  searchable = true,
  searchKey,
  searchPlaceholder = "Search…",
  pageSize = 10,
  className,
  isLoading = false,
  pagination = true,
  getRowId,
  onSelectionChange,
  onRowClick
}) {
  const [sorting, setSorting] = useState([]);
  const [columnFilters, setColumnFilters] = useState([]);
  const [globalFilter, setGlobalFilter] = useState("");
  const [rowSelection, setRowSelection] = useState({});
  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onGlobalFilterChange: setGlobalFilter,
    onRowSelectionChange: setRowSelection,
    getRowId,
    enableRowSelection: Boolean(onSelectionChange),
    state: {
      sorting,
      columnFilters,
      globalFilter,
      rowSelection
    },
    initialState: {
      pagination: {
        pageSize
      }
    }
  });
  useEffect(() => {
    if (!onSelectionChange) return;
    const selectedIds = table.getSelectedRowModel().rows.map((row) => String(row.id));
    onSelectionChange(selectedIds);
  }, [onSelectionChange, rowSelection, table]);
  const handleSearchChange = useCallback(
    (e) => {
      const value = e.target.value;
      if (searchKey) {
        table.getColumn(searchKey)?.setFilterValue(value);
      } else {
        setGlobalFilter(value);
      }
    },
    [searchKey, table]
  );
  const searchValue = searchKey ? table.getColumn(searchKey)?.getFilterValue() ?? "" : globalFilter;
  return /* @__PURE__ */ jsxs("div", { className: cn("space-y-4", className), children: [
    searchable && /* @__PURE__ */ jsx("div", { className: "flex items-center gap-2", children: /* @__PURE__ */ jsx(
      Input,
      {
        placeholder: searchPlaceholder,
        value: searchValue,
        onChange: handleSearchChange,
        className: "max-w-sm",
        "aria-label": searchPlaceholder
      }
    ) }),
    /* @__PURE__ */ jsx("div", { className: "rounded-md border", children: /* @__PURE__ */ jsxs("table", { className: "w-full text-sm", children: [
      /* @__PURE__ */ jsx("thead", { className: "bg-muted/50", children: table.getHeaderGroups().map((headerGroup) => /* @__PURE__ */ jsx("tr", { children: headerGroup.headers.map((header) => /* @__PURE__ */ jsx("th", { className: "px-4 py-3 text-left font-medium", scope: "col", children: header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext()) }, header.id)) }, headerGroup.id)) }),
      /* @__PURE__ */ jsx("tbody", { children: isLoading ? /* @__PURE__ */ jsx("tr", { children: /* @__PURE__ */ jsx("td", { colSpan: columns.length, className: "px-4 py-8 text-center text-muted-foreground", children: "Loading…" }) }) : table.getRowModel().rows.length > 0 ? table.getRowModel().rows.map((row) => /* @__PURE__ */ jsx(
        "tr",
        {
          className: cn(
            "border-t transition-colors",
            onRowClick ? "cursor-pointer hover:bg-muted/50" : "hover:bg-muted/50"
          ),
          onClick: onRowClick ? () => onRowClick(row.original) : void 0,
          children: row.getVisibleCells().map((cell) => /* @__PURE__ */ jsx("td", { className: "px-4 py-3", children: flexRender(cell.column.columnDef.cell, cell.getContext()) }, cell.id))
        },
        row.id
      )) : /* @__PURE__ */ jsx("tr", { children: /* @__PURE__ */ jsx("td", { colSpan: columns.length, className: "px-4 py-8 text-center text-muted-foreground", children: "No results found." }) }) })
    ] }) }),
    pagination !== false && /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxs("div", { className: "text-sm text-muted-foreground", children: [
        "Showing ",
        table.getRowModel().rows.length,
        " of ",
        data.length,
        " results"
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsx(
          Button,
          {
            variant: "outline",
            size: "sm",
            onClick: () => table.previousPage(),
            disabled: !table.getCanPreviousPage(),
            "aria-label": "Previous page",
            children: "Previous"
          }
        ),
        /* @__PURE__ */ jsxs("span", { className: "text-sm text-muted-foreground", children: [
          "Page ",
          table.getState().pagination.pageIndex + 1,
          " of ",
          table.getPageCount()
        ] }),
        /* @__PURE__ */ jsx(
          Button,
          {
            variant: "outline",
            size: "sm",
            onClick: () => table.nextPage(),
            disabled: !table.getCanNextPage(),
            "aria-label": "Next page",
            children: "Next"
          }
        )
      ] })
    ] })
  ] });
}
function createStatusBadge(config) {
  return ({ getValue }) => {
    const rawValue = String(getValue() ?? "");
    const status = config[rawValue];
    return /* @__PURE__ */ jsx(Badge, { variant: status?.variant || "default", children: status?.label || rawValue || "Unknown" });
  };
}
function createDateCell() {
  return ({ getValue }) => {
    const value = getValue();
    if (!value || typeof value !== "string") return "—";
    return formatDate(value);
  };
}
function createSelectColumn() {
  return {
    id: "select",
    header: ({ table }) => /* @__PURE__ */ jsx(
      "input",
      {
        type: "checkbox",
        "aria-label": "Select all rows",
        checked: table.getIsAllPageRowsSelected(),
        onChange: table.getToggleAllPageRowsSelectedHandler()
      }
    ),
    cell: ({ row }) => /* @__PURE__ */ jsx(
      "input",
      {
        type: "checkbox",
        "aria-label": `Select row ${row.id}`,
        checked: row.getIsSelected(),
        disabled: !row.getCanSelect(),
        onChange: row.getToggleSelectedHandler(),
        onClick: (e) => e.stopPropagation()
      }
    ),
    enableSorting: false,
    enableColumnFilter: false
  };
}
export {
  DataTable as D,
  createStatusBadge as a,
  createDateCell as b,
  createSelectColumn as c
};
