// Comments mention eval(userInput), value === NaN and i <= values.length.
// These are prose and must not trigger AST rules.
export function safeSum(values: number[]): number {
  let total = 0;
  for (let i = 0; i < values.length; i++) total += values[i]!;
  return total;
}

export function safeNaN(value: number): boolean {
  return Number.isNaN(value);
}
