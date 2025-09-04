import { execSync } from 'child_process';
import * as fs from 'node:fs';
import * as path from 'path';
import { AuthMethod } from 'src/entities/user.entity';

export function base64urlEncode(s: string) {
    return Buffer.from(s, 'utf8')
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

export function base64urlDecode(s: string) {
    return Buffer.from(
      s.replace(/-/g, '+').replace(/_/g, '/'),
      'base64',
    ).toString('utf8');
  }

export function providerDefaultNext(provider: string) {
    return provider === 'diia' ? '/profile/dashboard' : '/profile/dashboard';
  }
  
export function sanitizeNext(next: string | undefined, provider: string): string {
    const fallback = providerDefaultNext(provider);
    if (typeof next !== 'string') return fallback;
    const ok =
      next.startsWith('/') &&
      !next.startsWith('//') &&
      !next.includes('\r') &&
      !next.includes('\n');
    return ok ? next : fallback;
  }

export function saveSession(session: any) {
    return new Promise<void>((resolve, reject) => {
      session.save((err: any) => (err ? reject(err) : resolve()));
    });
  }
  
export function normalizeExpires(
    expires_at?: number | null,
    expires_in?: number | string | null,
  ): number | null {
    const inNum =
      typeof expires_in === 'string' ? parseInt(expires_in, 10) : expires_in;
    if (Number.isFinite(inNum as number)) {
      return Math.floor((Date.now() + (inNum as number) * 1000) / 1000); // UNIX seconds
    }
    return typeof expires_at === 'number' ? expires_at : null;
  }

export async function hashStableId(id: string): Promise<string> {
      const { createHash } = await import('crypto');
      return createHash('sha256').update(id, 'utf8').digest('hex');
    }

export function  maskStableId(id: string): string {
      const tail = id.slice(-4);
      return `${'*'.repeat(Math.max(0, id.length - 4))}${tail}`;
    }
  
export function  mapProviderToAuthMethod(p: string): AuthMethod {
      return p.toLowerCase() === 'google'
        ? AuthMethod.GOOGLE
        : AuthMethod.CREDENTIALS;
    }

export function loadCertBase64(path: string) {
  const der = fs.readFileSync(path);
  return der.toString('base64'); 
}

export function decryptUserInfo(
  encryptedUserInfo: string,
  privateKeyPath: string,
) {
  
  fs.writeFileSync('/tmp/data.base64', encryptedUserInfo);

  execSync(`
    cat /tmp/data.base64 | base64 -d > /tmp/data.der
    openssl smime -decrypt -in /tmp/data.der -inform DER -inkey ${privateKeyPath} -out /tmp/user.json
  `);

  const decrypted = fs.readFileSync('/tmp/user.json', 'utf8');
  return JSON.parse(decrypted);
}

export function getUtilsPath(filename: string) {
  const baseEnv = (process.env.EUSIGN_DIR || '').trim(); 
  const base = baseEnv || path.resolve(process.cwd(), 'dist', 'eusign');

  const candidates = [
    path.join(base, filename), 
    path.resolve(process.cwd(), 'dist', 'utils', filename), 
    path.resolve(process.cwd(), 'eusign', filename),
  ];

  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }

  throw new Error(
    `Файл ${filename} не знайдено. Ищется в:\n${candidates.join('\n')}`,
  );
}
