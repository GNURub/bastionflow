declare module "bun:sqlite" {
  type SqlitePrimitive = string | number | bigint | boolean | null | Uint8Array | Buffer;
  type SqliteBindings = SqlitePrimitive | Record<string, SqlitePrimitive>;

  export interface Statement<T = unknown> {
    all(...params: SqliteBindings[]): T[];
    get(...params: SqliteBindings[]): T | null;
    run(...params: SqliteBindings[]): { changes: number; lastInsertRowid: number | bigint };
    values(...params: SqliteBindings[]): unknown[][];
    finalize(): void;
    toString(): string;
  }

  export class Database {
    constructor(filename?: string, options?: { readonly?: boolean; create?: boolean; strict?: boolean; safeIntegers?: boolean });
    run(sql: string, ...params: SqliteBindings[]): { changes: number; lastInsertRowid: number | bigint };
    query<T = unknown>(sql: string): Statement<T>;
    prepare<T = unknown>(sql: string): Statement<T>;
    close(throwOnError?: boolean): void;
  }
}
