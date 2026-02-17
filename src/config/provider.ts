import path from 'node:path';
import fs from 'node:fs';
import Handlebars from 'handlebars';
import Provider, { Configuration, FindAccount, AccountClaims } from 'oidc-provider';
import { SqliteAdapter } from '../adapter.js';
import { getDb } from '../db.js';
import * as userRepo from '../repos/users.js';
import { getProviderJWKS } from './keys.js';

const ISSUER = process.env.ISSUER || 'http://localhost:3000';

/**
 * Find account by ID for oidc-provider
 * Returns claims for the ID token and userinfo endpoint
 */
const findAccount: FindAccount = async (ctx: any, id: string) => {
  const user = userRepo.findUserById(getDb(), id);

  if (!user) {
    return undefined;
  }

  return {
    accountId: user.id,
    async claims(use: string, scope: string) {
      const claims: AccountClaims = {
        sub: id,
      };

      // Parse scope string into array
      const scopes = scope.split(' ');

      if (scopes.includes('profile')) {
        claims.name = user.name;
        claims.preferred_username = user.username;
      }

      if (scopes.includes('email')) {
        claims.email = user.email;
        claims.email_verified = user.emailVerified;
      }

      return claims;
    },
  };
};

// Device flow templates — compiled at startup, rendered into Koa ctx.body
const VIEWS_DIR = path.join(import.meta.dir, '..', 'views', 'interaction');
const deviceInputTemplate = Handlebars.compile(
  fs.readFileSync(path.join(VIEWS_DIR, 'device-input.hbs'), 'utf-8')
);
const deviceConfirmTemplate = Handlebars.compile(
  fs.readFileSync(path.join(VIEWS_DIR, 'device-confirm.hbs'), 'utf-8')
);
const deviceSuccessTemplate = Handlebars.compile(
  fs.readFileSync(path.join(VIEWS_DIR, 'device-success.hbs'), 'utf-8')
);

/**
 * Create and configure the OIDC provider
 */
export async function createProvider(): Promise<Provider> {
  const jwks = await getProviderJWKS();

  const configuration: Configuration = {
    // Adapter for persistence
    adapter: SqliteAdapter,

    // Account lookup
    findAccount,

    // Signing keys
    jwks: { keys: jwks },

    // Supported claims
    claims: {
      openid: ['sub'],
      profile: ['name', 'preferred_username'],
      email: ['email', 'email_verified'],
    },

    // Supported scopes
    scopes: ['openid', 'profile', 'email', 'offline_access'],

    // Response types
    responseTypes: ['code', 'code id_token', 'id_token', 'id_token token'],

    // Client defaults
    clientDefaults: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
    },

    // Features
    features: {
      // Dynamic client registration
      registration: {
        enabled: true,
        idFactory: () => `client-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        secretFactory: () => `secret-${Date.now()}-${Math.random().toString(36).slice(2, 16)}`,
      },

      // Registration management (read/update/delete)
      registrationManagement: {
        enabled: true,
        rotateRegistrationAccessToken: false,
      },

      // Disable default dev interactions (we use custom ones)
      devInteractions: { enabled: false },

      // Token introspection
      introspection: { enabled: true },

      // Token revocation
      revocation: { enabled: true },

      // Device Authorization Grant (RFC 8628)
      deviceFlow: {
        enabled: true,
        charset: 'base-20',
        mask: '****-****',
        userCodeInputSource: async (ctx: any, form: string, out: any, err: any) => {
          if (err || out) {
            console.error('[DEVICE] userCodeInputSource error:', {
              errMessage: err?.message,
              errDescription: err?.error_description,
              errDetail: err?.error_detail,
              errName: err?.name,
              outError: out?.error,
              outDescription: out?.error_description,
            });
          }
          ctx.type = 'html';
          ctx.body = deviceInputTemplate({
            title: 'Device Activation',
            formHtml: form,
            error: err?.error_description || out?.error_description || err?.message || out?.error,
          });
        },
        userCodeConfirmSource: async (ctx: any, form: string, client: any, deviceInfo: any, userCode: string) => {
          ctx.type = 'html';
          ctx.body = deviceConfirmTemplate({
            title: 'Authorize Device',
            formHtml: form,
            clientName: client.clientName || client.clientId,
            clientId: client.clientId,
            userCode,
            scope: deviceInfo.scope?.split(' ') || [],
          });
        },
        successSource: async (ctx: any) => {
          ctx.type = 'html';
          ctx.body = deviceSuccessTemplate({
            title: 'Device Authorized',
          });
        },
      },

    },

    // PKCE - required for public clients
    pkce: {
      required: (ctx: any, client: any) => {
        return client.tokenEndpointAuthMethod === 'none';
      },
    },

    // Interaction settings
    interactions: {
      url: (ctx: any, interaction: any) => `/interaction/${interaction.uid}`,
    },

    // Cookie settings
    cookies: {
      keys: [process.env.SESSION_SECRET || 'dev-secret-change-me'],
      short: {
        signed: true,
        httpOnly: true,
        maxAge: 10 * 60 * 1000, // 10 minutes for interactions
      },
      long: {
        signed: true,
        httpOnly: true,
        maxAge: 14 * 24 * 60 * 60 * 1000, // 14 days for sessions
      },
    },

    // Token TTLs
    ttl: {
      AccessToken: 60 * 60, // 1 hour
      AuthorizationCode: 60, // 1 minute
      IdToken: 60 * 60, // 1 hour
      RefreshToken: 14 * 24 * 60 * 60, // 14 days
      BackchannelAuthenticationRequest: 10 * 60, // 10 minutes (CIBA)
      ClientCredentials: 60 * 60, // 1 hour
      DeviceCode: 10 * 60, // 10 minutes
      Interaction: 60 * 60, // 1 hour
      Session: 14 * 24 * 60 * 60, // 14 days
      Grant: 14 * 24 * 60 * 60, // 14 days
    },

    // Custom error rendering
    renderError: async (ctx, out, error) => {
      ctx.type = 'html';
      ctx.body = `<!DOCTYPE html>
<html>
<head>
  <title>Error - OIDC Lab</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
  <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
    <h1 class="text-2xl font-bold text-red-600 mb-4">Error</h1>
    <p class="text-gray-700 mb-2"><strong>Error:</strong> ${out.error}</p>
    ${out.error_description ? `<p class="text-gray-600 mb-4">${out.error_description}</p>` : ''}
    <a href="/" class="text-blue-500 hover:underline">Return to home</a>
  </div>
</body>
</html>`;
    },

    // Extra params allowed
    extraParams: ['login_hint', 'prompt', 'acr_values'],

    // Enable CORS for SPA clients
    clientBasedCORS: (ctx, origin, client) => {
      return true; // Allow all origins in dev
    },
  };

  const provider = new Provider(ISSUER, configuration);

  // Trust proxy headers (for X-Forwarded-*)
  provider.proxy = true;

  return provider;
}

export default createProvider;
