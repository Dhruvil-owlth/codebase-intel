export function firstInvoice(amount: number, fee: number): number {
  const subtotal = amount + fee;
  const rounded = Math.round(subtotal * 100) / 100;
  const minimum = Math.max(0, rounded);
  return minimum;
}

export function secondInvoice(amount: number, fee: number): number {
  const subtotal = amount + fee;
  const rounded = Math.round(subtotal * 100) / 100;
  const minimum = Math.max(0, rounded);
  return minimum;
}
