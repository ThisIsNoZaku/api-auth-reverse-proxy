export class HttpError extends Error {
  constructor(public readonly status: number, public readonly code: string) {
    super(code);
  }
}

export function reject(condition: unknown, status: number, code: string): asserts condition {
  if (!condition) throw new HttpError(status, code);
}
