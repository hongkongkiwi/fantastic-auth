import { jsxs, jsx, Fragment } from "react/jsx-runtime";
import * as React from "react";
import { useReactTable, getPaginationRowModel, getFilteredRowModel, getSortedRowModel, getCoreRowModel, flexRender } from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Search, Download, Filter, X, MoreHorizontal, ChevronUp, ChevronDown, ArrowUpDown, ChevronsLeft, ChevronLeft, ChevronRight, ChevronsRight } from "lucide-react";
import { useReducedMotion, AnimatePresence, motion } from "framer-motion";
import { B as Button, j as cn } from "./router-BDwxh4pl.js";
import { I as Input } from "./Input-C7MrN6IE.js";
import { B as Badge } from "./Badge-DmGWtXSM.js";
import { a as Skeleton } from "./Skeleton-CdKpSX4m.js";
import { C as Checkbox } from "./Checkbox-Dbk2YhaG.js";
import { D as DropdownMenu, a as DropdownMenuTrigger, b as DropdownMenuContent, d as DropdownMenuCheckboxItem, e as DropdownMenuSeparator, c as DropdownMenuItem } from "./DropdownMenu-CUcXj7WN.js";
function DataTable({
  columns,
  data,
  isLoading,
  searchable = true,
  searchPlaceholder = "Search…",
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
  exportFileName = "export",
  bulkActions,
  enableRowSelection = true
}) {
  const [sorting, setSorting] = React.useState([]);
  const [columnFilters, setColumnFilters] = React.useState([]);
  const [globalFilter, setGlobalFilter] = React.useState("");
  const [searchValue, setSearchValue] = React.useState("");
  const deferredSearch = React.useDeferredValue(searchValue);
  const [columnVisibility, setColumnVisibility] = React.useState({});
  const [rowSelection, setRowSelection] = React.useState({});
  const prefersReducedMotion = useReducedMotion();
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
      pagination: {
        pageSize,
        pageIndex: 0
      }
    }
  });
  React.useEffect(() => {
    setGlobalFilter(deferredSearch);
  }, [deferredSearch]);
  const tableContainerRef = React.useRef(null);
  const rows = table.getRowModel().rows;
  const shouldVirtualize = rows.length > 50;
  const rowVirtualizer = useVirtualizer({
    count: shouldVirtualize ? rows.length : 0,
    getScrollElement: () => tableContainerRef.current,
    estimateSize: () => 56,
    overscan: 8
  });
  const virtualRows = rowVirtualizer.getVirtualItems();
  const paddingTop = shouldVirtualize && virtualRows.length > 0 ? virtualRows[0].start : 0;
  const paddingBottom = shouldVirtualize && virtualRows.length > 0 ? rowVirtualizer.getTotalSize() - virtualRows[virtualRows.length - 1].end : 0;
  React.useEffect(() => {
    if (onSelectionChange) {
      const selectedIds = Object.keys(rowSelection).filter((id) => rowSelection[id]);
      onSelectionChange(selectedIds);
    }
  }, [rowSelection, onSelectionChange]);
  React.useEffect(() => {
    if (selectedRows) {
      const selection = {};
      selectedRows.forEach((id) => {
        selection[id] = true;
      });
      setRowSelection(selection);
    }
  }, [selectedRows]);
  const handleExport = () => {
    const rows2 = table.getFilteredRowModel().rows;
    const headers = columns.filter((col) => col.id !== "select" && col.id !== "actions").map((col) => col.header);
    const csvContent = [
      headers.join(","),
      ...rows2.map(
        (row) => columns.filter((col) => col.id !== "select" && col.id !== "actions").map((col) => {
          const value = row.getValue(col.id);
          const stringValue = String(value ?? "");
          return `"${stringValue.replace(/"/g, '""')}"`;
        }).join(",")
      )
    ].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${exportFileName}_${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };
  const selectedCount = Object.keys(rowSelection).filter((id) => rowSelection[id]).length;
  return /* @__PURE__ */ jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxs("div", { className: "flex flex-col sm:flex-row sm:items-center justify-between gap-4", children: [
      /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2 flex-1", children: [
        searchable && /* @__PURE__ */ jsxs("div", { className: "relative flex-1 max-w-sm", children: [
          /* @__PURE__ */ jsx(Search, { className: "absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground", "aria-hidden": "true" }),
          /* @__PURE__ */ jsx(
            Input,
            {
              placeholder: searchPlaceholder,
              value: searchValue,
              onChange: (e) => setSearchValue(e.target.value),
              className: "pl-10",
              "aria-label": searchPlaceholder,
              name: "table-search",
              autoComplete: "off"
            }
          )
        ] }),
        toolbar
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
        selectedCount > 0 && /* @__PURE__ */ jsxs(Badge, { variant: "secondary", children: [
          selectedCount,
          " selected"
        ] }),
        exportable && /* @__PURE__ */ jsx(
          Button,
          {
            variant: "outline",
            size: "sm",
            leftIcon: /* @__PURE__ */ jsx(Download, { className: "h-4 w-4" }),
            onClick: handleExport,
            children: "Export"
          }
        ),
        /* @__PURE__ */ jsxs(DropdownMenu, { children: [
          /* @__PURE__ */ jsx(DropdownMenuTrigger, { asChild: true, children: /* @__PURE__ */ jsx(Button, { variant: "outline", size: "sm", leftIcon: /* @__PURE__ */ jsx(Filter, { className: "h-4 w-4" }), children: "Columns" }) }),
          /* @__PURE__ */ jsx(DropdownMenuContent, { align: "end", className: "w-48", children: table.getAllColumns().filter((column) => column.getCanHide()).map((column) => {
            return /* @__PURE__ */ jsx(
              DropdownMenuCheckboxItem,
              {
                className: "capitalize",
                checked: column.getIsVisible(),
                onCheckedChange: (value) => column.toggleVisibility(!!value),
                children: column.id
              },
              column.id
            );
          }) })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsx(AnimatePresence, { children: selectedCount > 0 && bulkActions && bulkActions.length > 0 && /* @__PURE__ */ jsxs(
      motion.div,
      {
        initial: { opacity: 0, y: -10 },
        animate: { opacity: 1, y: 0 },
        exit: { opacity: 0, y: -10 },
        className: "flex items-center justify-between p-3 bg-primary/5 border rounded-lg",
        children: [
          /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
            /* @__PURE__ */ jsx(
              Checkbox,
              {
                checked: table.getIsAllPageRowsSelected(),
                indeterminate: table.getIsSomePageRowsSelected(),
                onCheckedChange: (checked) => table.toggleAllPageRowsSelected(!!checked),
                label: `${selectedCount} selected`
              }
            ),
            /* @__PURE__ */ jsxs(
              Button,
              {
                variant: "ghost",
                size: "sm",
                onClick: () => table.toggleAllRowsSelected(false),
                children: [
                  /* @__PURE__ */ jsx(X, { className: "h-4 w-4 mr-1" }),
                  "Clear"
                ]
              }
            )
          ] }),
          /* @__PURE__ */ jsx("div", { className: "flex items-center gap-2", children: bulkActions.length <= 2 ? bulkActions.map((action) => /* @__PURE__ */ jsx(
            Button,
            {
              variant: action.variant === "destructive" ? "destructive" : "outline",
              size: "sm",
              leftIcon: action.icon,
              onClick: () => {
                const selectedData = table.getSelectedRowModel().rows.map((row) => row.original);
                action.onClick(selectedData);
              },
              disabled: action.disabled,
              children: action.label
            },
            action.id
          )) : /* @__PURE__ */ jsxs(Fragment, { children: [
            bulkActions.slice(0, 1).map((action) => /* @__PURE__ */ jsx(
              Button,
              {
                variant: action.variant === "destructive" ? "destructive" : "outline",
                size: "sm",
                leftIcon: action.icon,
                onClick: () => {
                  const selectedData = table.getSelectedRowModel().rows.map((row) => row.original);
                  action.onClick(selectedData);
                },
                disabled: action.disabled,
                children: action.label
              },
              action.id
            )),
            /* @__PURE__ */ jsxs(DropdownMenu, { children: [
              /* @__PURE__ */ jsx(DropdownMenuTrigger, { asChild: true, children: /* @__PURE__ */ jsx(Button, { variant: "outline", size: "sm", leftIcon: /* @__PURE__ */ jsx(MoreHorizontal, { className: "h-4 w-4" }), children: "More Actions" }) }),
              /* @__PURE__ */ jsx(DropdownMenuContent, { align: "end", children: bulkActions.slice(1).map((action, index) => /* @__PURE__ */ jsxs(React.Fragment, { children: [
                index > 0 && /* @__PURE__ */ jsx(DropdownMenuSeparator, {}),
                /* @__PURE__ */ jsxs(
                  DropdownMenuItem,
                  {
                    onClick: () => {
                      const selectedData = table.getSelectedRowModel().rows.map((row) => row.original);
                      action.onClick(selectedData);
                    },
                    disabled: action.disabled,
                    className: action.variant === "destructive" ? "text-destructive" : "",
                    children: [
                      action.icon && /* @__PURE__ */ jsx("span", { className: "mr-2", children: action.icon }),
                      action.label
                    ]
                  }
                )
              ] }, action.id)) })
            ] })
          ] }) })
        ]
      }
    ) }),
    /* @__PURE__ */ jsxs("div", { className: "rounded-xl border bg-card overflow-hidden", children: [
      /* @__PURE__ */ jsx("div", { ref: tableContainerRef, className: "max-h-[560px] overflow-auto", children: /* @__PURE__ */ jsxs("table", { className: "w-full text-sm", children: [
        /* @__PURE__ */ jsx("thead", { className: "bg-muted/50", children: table.getHeaderGroups().map((headerGroup) => /* @__PURE__ */ jsx("tr", { children: headerGroup.headers.map((header) => /* @__PURE__ */ jsx(
          "th",
          {
            className: cn(
              "px-4 py-3 text-left font-medium text-muted-foreground"
            ),
            children: /* @__PURE__ */ jsx("div", { className: "flex items-center gap-2", children: header.isPlaceholder ? null : header.column.getCanSort() ? /* @__PURE__ */ jsxs(
              "button",
              {
                type: "button",
                className: "inline-flex items-center gap-2 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                onClick: header.column.getToggleSortingHandler(),
                "aria-label": `Sort by ${String(
                  header.column.columnDef.header ?? header.id
                )}`,
                children: [
                  flexRender(
                    header.column.columnDef.header,
                    header.getContext()
                  ),
                  /* @__PURE__ */ jsx("span", { className: "text-muted-foreground/50", children: header.column.getIsSorted() === "asc" ? /* @__PURE__ */ jsx(ChevronUp, { className: "h-4 w-4", "aria-hidden": "true" }) : header.column.getIsSorted() === "desc" ? /* @__PURE__ */ jsx(ChevronDown, { className: "h-4 w-4", "aria-hidden": "true" }) : /* @__PURE__ */ jsx(ArrowUpDown, { className: "h-3 w-3", "aria-hidden": "true" }) })
                ]
              }
            ) : flexRender(
              header.column.columnDef.header,
              header.getContext()
            ) })
          },
          header.id
        )) }, headerGroup.id)) }),
        /* @__PURE__ */ jsx("tbody", { className: "divide-y", children: isLoading ? Array.from({ length: 5 }).map((_, i) => /* @__PURE__ */ jsx("tr", { className: "border-b", children: columns.map((_2, j) => /* @__PURE__ */ jsx("td", { className: "px-4 py-3", children: /* @__PURE__ */ jsx(Skeleton, { className: "h-4 w-full" }) }, j)) }, i)) : rows.length ? /* @__PURE__ */ jsx(Fragment, { children: shouldVirtualize ? /* @__PURE__ */ jsxs(Fragment, { children: [
          paddingTop > 0 && /* @__PURE__ */ jsx("tr", { children: /* @__PURE__ */ jsx("td", { style: { height: paddingTop }, colSpan: columns.length }) }),
          virtualRows.map((virtualRow, index) => {
            const row = rows[virtualRow.index];
            return /* @__PURE__ */ jsx(
              motion.tr,
              {
                initial: prefersReducedMotion ? false : { opacity: 0 },
                animate: { opacity: 1 },
                className: cn(
                  "transition-colors",
                  onRowClick && "cursor-pointer hover:bg-muted/50",
                  row.getIsSelected() && "bg-primary/5"
                ),
                onClick: () => onRowClick?.(row.original),
                onKeyDown: (event) => {
                  if (!onRowClick) return;
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onRowClick(row.original);
                  }
                },
                role: onRowClick ? "button" : void 0,
                tabIndex: onRowClick ? 0 : void 0,
                transition: prefersReducedMotion ? { duration: 0 } : { delay: index * 0.02 },
                children: row.getVisibleCells().map((cell) => /* @__PURE__ */ jsx("td", { className: "px-4 py-3", children: flexRender(cell.column.columnDef.cell, cell.getContext()) }, cell.id))
              },
              row.id
            );
          }),
          paddingBottom > 0 && /* @__PURE__ */ jsx("tr", { children: /* @__PURE__ */ jsx("td", { style: { height: paddingBottom }, colSpan: columns.length }) })
        ] }) : rows.map((row, index) => /* @__PURE__ */ jsx(
          motion.tr,
          {
            initial: prefersReducedMotion ? false : { opacity: 0 },
            animate: { opacity: 1 },
            className: cn(
              "transition-colors",
              onRowClick && "cursor-pointer hover:bg-muted/50",
              row.getIsSelected() && "bg-primary/5"
            ),
            onClick: () => onRowClick?.(row.original),
            onKeyDown: (event) => {
              if (!onRowClick) return;
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onRowClick(row.original);
              }
            },
            role: onRowClick ? "button" : void 0,
            tabIndex: onRowClick ? 0 : void 0,
            transition: prefersReducedMotion ? { duration: 0 } : { delay: index * 0.02 },
            children: row.getVisibleCells().map((cell) => /* @__PURE__ */ jsx("td", { className: "px-4 py-3", children: flexRender(cell.column.columnDef.cell, cell.getContext()) }, cell.id))
          },
          row.id
        )) }) : /* @__PURE__ */ jsx("tr", { children: /* @__PURE__ */ jsx(
          "td",
          {
            colSpan: columns.length,
            className: "px-4 py-12 text-center text-muted-foreground",
            children: emptyState || /* @__PURE__ */ jsxs("div", { className: "flex flex-col items-center gap-2", children: [
              /* @__PURE__ */ jsx(Search, { className: "h-8 w-8 text-muted-foreground/50" }),
              /* @__PURE__ */ jsx("p", { children: "No results found" })
            ] })
          }
        ) }) })
      ] }) }),
      pagination && /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between px-4 py-3 border-t bg-muted/30", children: [
        /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2 text-sm text-muted-foreground", children: [
          /* @__PURE__ */ jsxs("span", { children: [
            "Page ",
            table.getState().pagination.pageIndex + 1,
            " of",
            " ",
            table.getPageCount()
          ] }),
          /* @__PURE__ */ jsxs("span", { className: "hidden sm:inline", children: [
            "(",
            table.getFilteredRowModel().rows.length,
            " total)"
          ] })
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsx(
            "select",
            {
              value: table.getState().pagination.pageSize,
              onChange: (e) => table.setPageSize(Number(e.target.value)),
              className: "h-8 rounded-md border border-input bg-background px-2 text-sm",
              "aria-label": "Rows per page",
              children: pageSizeOptions.map((size) => /* @__PURE__ */ jsxs("option", { value: size, children: [
                size,
                " / page"
              ] }, size))
            }
          ),
          /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-1", children: [
            /* @__PURE__ */ jsx(
              Button,
              {
                variant: "outline",
                size: "icon-sm",
                onClick: () => table.setPageIndex(0),
                disabled: !table.getCanPreviousPage(),
                "aria-label": "First page",
                children: /* @__PURE__ */ jsx(ChevronsLeft, { className: "h-4 w-4" })
              }
            ),
            /* @__PURE__ */ jsx(
              Button,
              {
                variant: "outline",
                size: "icon-sm",
                onClick: () => table.previousPage(),
                disabled: !table.getCanPreviousPage(),
                "aria-label": "Previous page",
                children: /* @__PURE__ */ jsx(ChevronLeft, { className: "h-4 w-4" })
              }
            ),
            /* @__PURE__ */ jsx(
              Button,
              {
                variant: "outline",
                size: "icon-sm",
                onClick: () => table.nextPage(),
                disabled: !table.getCanNextPage(),
                "aria-label": "Next page",
                children: /* @__PURE__ */ jsx(ChevronRight, { className: "h-4 w-4" })
              }
            ),
            /* @__PURE__ */ jsx(
              Button,
              {
                variant: "outline",
                size: "icon-sm",
                onClick: () => table.setPageIndex(table.getPageCount() - 1),
                disabled: !table.getCanNextPage(),
                "aria-label": "Last page",
                children: /* @__PURE__ */ jsx(ChevronsRight, { className: "h-4 w-4" })
              }
            )
          ] })
        ] })
      ] })
    ] })
  ] });
}
function createSelectColumn() {
  return {
    id: "select",
    header: ({ table }) => /* @__PURE__ */ jsx("div", { className: "flex justify-center", children: /* @__PURE__ */ jsx(
      Checkbox,
      {
        checked: table.getIsAllPageRowsSelected(),
        indeterminate: table.getIsSomePageRowsSelected(),
        onCheckedChange: (checked) => table.toggleAllPageRowsSelected(!!checked)
      }
    ) }),
    cell: ({ row }) => /* @__PURE__ */ jsx("div", { className: "flex justify-center", onClick: (e) => e.stopPropagation(), children: /* @__PURE__ */ jsx(
      Checkbox,
      {
        checked: row.getIsSelected(),
        onCheckedChange: (checked) => row.toggleSelected(!!checked)
      }
    ) }),
    enableSorting: false,
    enableHiding: false,
    size: 40
  };
}
function createStatusBadge(statusMap) {
  return ({ getValue }) => {
    const status = String(getValue() ?? "unknown");
    const config = statusMap[status] || { label: status, variant: "default" };
    return /* @__PURE__ */ jsx(Badge, { variant: config.variant, children: config.label });
  };
}
function createDateCell() {
  return ({ getValue }) => {
    const value = getValue();
    if (!value) return /* @__PURE__ */ jsx("span", { className: "text-muted-foreground", children: "—" });
    const date = value instanceof Date ? value : new Date(String(value));
    if (Number.isNaN(date.getTime())) {
      return /* @__PURE__ */ jsx("span", { className: "text-muted-foreground", children: "—" });
    }
    return /* @__PURE__ */ jsx("span", { className: "text-muted-foreground", children: new Intl.DateTimeFormat("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric"
    }).format(date) });
  };
}
export {
  DataTable as D,
  createStatusBadge as a,
  createDateCell as b,
  createSelectColumn as c
};
