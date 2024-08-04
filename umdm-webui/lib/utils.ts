import { randomBytes } from 'crypto';

export function generateUrlSafeSecretKey(length: number = 32): string {
    const buffer = randomBytes(length);
    return buffer.toString('base64url');
}
