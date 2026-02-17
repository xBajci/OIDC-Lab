import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { generateKeyPair, exportJWK } from 'jose';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JWKS_PATH = path.join(__dirname, '../../.jwks.json');

export interface JWK {
  kty: string;
  kid: string;
  use: string;
  alg: string;
  [key: string]: unknown;
}

export interface JWKS {
  keys: JWK[];
}

/**
 * Generate a new RSA key pair for signing
 */
async function generateSigningKey(): Promise<JWK> {
  const { privateKey } = await generateKeyPair('RS256', {
    extractable: true,
  });

  const jwk = await exportJWK(privateKey);

  return {
    ...jwk,
    kid: `sig-${Date.now()}`,
    use: 'sig',
    alg: 'RS256',
  } as JWK;
}

/**
 * Load or generate JWKS
 * Auto-generates a signing key on first run, stores it in .jwks.json
 */
export async function loadOrGenerateJWKS(): Promise<JWKS> {
  // Try to load existing keys
  if (existsSync(JWKS_PATH)) {
    try {
      const data = readFileSync(JWKS_PATH, 'utf-8');
      const jwks = JSON.parse(data) as JWKS;
      console.log(`Loaded ${jwks.keys.length} keys from ${JWKS_PATH}`);
      return jwks;
    } catch (error) {
      console.warn('Failed to load existing JWKS, generating new keys:', error);
    }
  }

  // Generate new keys - only signing key, encryption key requires
  // additional provider config to be useful
  console.log('Generating new JWKS...');

  const signingKey = await generateSigningKey();

  const jwks: JWKS = {
    keys: [signingKey],
  };

  // Save to file
  writeFileSync(JWKS_PATH, JSON.stringify(jwks, null, 2));
  console.log(`Generated and saved new JWKS to ${JWKS_PATH}`);

  return jwks;
}

/**
 * Get the JWKS as an array of keys for oidc-provider
 */
export async function getProviderJWKS(): Promise<JWK[]> {
  const jwks = await loadOrGenerateJWKS();
  return jwks.keys;
}

export default { loadOrGenerateJWKS, getProviderJWKS };
