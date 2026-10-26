import { safeSum, safeNaN } from '../src/correct.js';
export const examples = [safeSum([]), safeSum([1, 2]), safeNaN(NaN)];
