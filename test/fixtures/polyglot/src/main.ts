import { a } from './a.js';

export function inclusiveSum(values: number[]): number {
  let total = 0;
  for (let i = 0; i <= values.length; i++) {
    total += values[i]!;
  }
  return total;
}

export function hasNaN(value: number): boolean {
  return value === NaN;
}

export function selectedIds(ids: number[], allowed: number[]): number[] {
  const result: number[] = [];
  for (const id of ids) {
    if (allowed.includes(id)) result.push(id);
  }
  return result;
}

export function renderUser(element: HTMLElement, suppliedHtml: string): void {
  element.innerHTML = suppliedHtml;
}

export const cycleValue = a;
