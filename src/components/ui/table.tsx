import * as React from "react";
import { cn } from "@/lib/utils";

export function Table({ className, ...props }: React.HTMLAttributes<HTMLTableElement>): React.ReactElement {
  return <table className={cn("block w-full min-w-full caption-bottom border-separate border-spacing-0 text-sm", className)} {...props} />;
}

export function TableHeader({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>): React.ReactElement {
  return <thead className={cn("block rounded-t-lg border-b border-white/10 bg-black/25 text-muted-foreground backdrop-blur supports-[backdrop-filter]:bg-black/20", className)} {...props} />;
}

export function TableBody({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>): React.ReactElement {
  return (
    <tbody
      className={cn(
        "block max-h-[420px] overflow-y-auto overscroll-contain rounded-b-lg [scrollbar-color:rgba(245,158,11,.45)_rgba(255,255,255,.06)] [scrollbar-width:thin]",
        "[&_tr:last-child]:border-0",
        className
      )}
      {...props}
    />
  );
}

export function TableRow({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>): React.ReactElement {
  return <tr className={cn("table w-full table-fixed border-b border-white/10 transition-colors hover:bg-amber-500/[0.04]", className)} {...props} />;
}

export function TableHead({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>): React.ReactElement {
  return <th className={cn("h-10 overflow-hidden text-ellipsis whitespace-nowrap px-3 text-left align-middle text-xs font-medium uppercase tracking-wide text-muted-foreground", className)} {...props} />;
}

export function TableCell({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>): React.ReactElement {
  return <td className={cn("overflow-hidden text-ellipsis px-3 py-3 align-middle", className)} {...props} />;
}
