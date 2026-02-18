import { Router, Request, Response, NextFunction } from 'express';
import * as client from 'openid-client';
import crypto from 'node:crypto';
import { getDb } from '../db.js';
import * as flowConfigRepo from '../repos/flow-configs.js';
import * as credRepo from '../repos/client-credentials.js';
import { ISSUER } from '../config/env.js';

// Extend session type
declare module 'express-session' {
  interface SessionData {
    pkceCodeVerifier?: string;
    state?: string;
    nonce?: string;
    flowConfig?: {
      issuer: string;
      clientId: string;
      clientSecret?: string;
    };
    deviceAuthResponse?: {
      device_code: string;
      user_code: string;
      verification_uri: string;
      verification_uri_complete?: string;
      expires_in: number;
      interval?: number;
    };
    deviceTokenResponse?: {
      access_token: string;
      id_token?: string;
      refresh_token?: string;
      token_type?: string;
      expires_in?: number;
      scope?: string;
    };
  }
}

// Flow presets
const FLOW_PRESETS = {
  serverSide: {
    name: 'Server-Side Web App',
    tooltip:
      'Your app has a backend server (Node.js, Python, etc.) that exchanges the authorization code for tokens server-to-server. The browser never sees the tokens - only a short-lived authorization code passes through the URL. This is the standard flow for traditional web apps built with Express, Django, Rails, etc. Includes offline_access for refresh tokens.',
    config: {
      responseType: 'code',
      scope: 'openid profile email offline_access',
      pkceEnabled: true,
      stateEnabled: true,
      nonceEnabled: true,
    },
  },
  implicitSpa: {
    name: 'Frontend-Only SPA (Implicit)',
    tooltip:
      "Your app runs entirely in the browser with no backend. Since there's no server to exchange a code, tokens are returned directly in the URL fragment (#). The browser can read them but they're never sent to a server. NOTE: This flow is considered legacy and less secure - tokens in URLs can leak via browser history and referrer headers. Modern SPAs should use Authorization Code + PKCE instead.",
    config: {
      responseType: 'id_token token',
      scope: 'openid profile email',
      pkceEnabled: false,
      stateEnabled: true,
      nonceEnabled: true,
    },
  },
  modernSpa: {
    name: 'Modern SPA (Auth Code + PKCE)',
    tooltip:
      "The current best practice for single-page apps. Uses authorization code flow like a server app, but with PKCE (Proof Key for Code Exchange) instead of a client secret - because a browser app can't keep secrets. An attacker who intercepts the code can't use it without the PKCE verifier that only your app knows. Requires a 'public client' (no client_secret, token_endpoint_auth_method: none).",
    config: {
      responseType: 'code',
      scope: 'openid profile email',
      pkceEnabled: true,
      stateEnabled: true,
      nonceEnabled: true,
    },
  },
  mostSecure: {
    name: 'Most Secure (Best Practice)',
    tooltip:
      'Follows OAuth 2.1 / FAPI security recommendations: Authorization Code + PKCE only, minimal scope (just openid - request more only when needed), forced re-consent on each flow, all protections enabled. This is what security auditors want to see.',
    config: {
      responseType: 'code',
      scope: 'openid',
      pkceEnabled: true,
      stateEnabled: true,
      nonceEnabled: true,
      extraParams: { prompt: 'consent' },
    },
  },
  deviceFlow: {
    name: 'Device Flow (RFC 8628)',
    tooltip:
      'Simulates a limited-input device (like a TV or CLI tool) that cannot open a browser. The device displays a user code and verification URL. You open the URL in a separate browser tab, enter the code, and authorize. The device polls the token endpoint until you authorize. Uses the Device Authorization Grant.',
    config: {
      responseType: 'code',
      scope: 'openid profile email',
      pkceEnabled: false,
      stateEnabled: false,
      nonceEnabled: false,
    },
  },
};

export function createFlowRouter(): Router {
  const router = Router();

  /**
   * GET / - Flow launcher form with history
   */
  router.get('/', async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Get recent flow configurations
      const recentFlows = flowConfigRepo.listRecentFlowConfigs(getDb(), 10);

      res.render('flow/index', {
        title: 'Flow Starter',
        activeNav: 'flow',
        presets: FLOW_PRESETS,
        defaults: {
          issuer: ISSUER,
          redirectUri: `${ISSUER}/flow/callback`,
          responseType: 'code',
          scope: 'openid profile email',
          pkceEnabled: true,
          stateEnabled: true,
          nonceEnabled: true,
        },
        recentFlows,
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /start - Start an OIDC flow
   */
  router.post('/start', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const {
        issuer,
        clientId,
        clientSecret,
        responseType,
        scope,
        redirectUri,
        pkceEnabled,
        stateEnabled,
        nonceEnabled,
        extraParams,
      } = req.body;

      // Discover the OIDC provider (allow HTTP for localhost dev)
      // Use ClientSecretBasic auth when secret is present (default is ClientSecretPost)
      const config = await client.discovery(
        new URL(issuer),
        clientId,
        clientSecret || undefined,
        clientSecret ? client.ClientSecretBasic(clientSecret) : undefined,
        { execute: [client.allowInsecureRequests] }
      );

      // Build authorization URL parameters
      const params: Record<string, string> = {
        redirect_uri: redirectUri,
        scope,
        response_type: responseType,
      };

      // PKCE
      let codeVerifier: string | undefined;
      if (pkceEnabled === 'on') {
        codeVerifier = client.randomPKCECodeVerifier();
        const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
        params.code_challenge = codeChallenge;
        params.code_challenge_method = 'S256';
      }

      // State
      let state: string | undefined;
      if (stateEnabled === 'on') {
        state = crypto.randomBytes(16).toString('hex');
        params.state = state;
      }

      // Nonce
      let nonce: string | undefined;
      if (nonceEnabled === 'on') {
        nonce = crypto.randomBytes(16).toString('hex');
        params.nonce = nonce;
      }

      // Extra params
      if (extraParams) {
        try {
          const extra = JSON.parse(extraParams);
          Object.assign(params, extra);
        } catch {
          // Ignore invalid JSON
        }
      }

      // OIDC spec requires prompt=consent when offline_access is requested
      // Without it, oidc-provider silently strips offline_access from the scope
      if (scope.includes('offline_access') && !params.prompt) {
        params.prompt = 'consent';
      }

      // Store in session
      req.session.pkceCodeVerifier = codeVerifier;
      req.session.state = state;
      req.session.nonce = nonce;
      req.session.flowConfig = {
        issuer,
        clientId,
        clientSecret,
      };

      // Save flow config to history
      flowConfigRepo.createFlowConfig(getDb(), {
        issuer,
        clientId,
        clientSecret,
        responseType,
        scope,
        redirectUri,
        pkceEnabled: pkceEnabled === 'on',
        stateEnabled: stateEnabled === 'on',
        nonceEnabled: nonceEnabled === 'on',
        extraParams: extraParams ? JSON.parse(extraParams || '{}') : undefined,
      });

      // Build the authorization URL
      const authUrl = client.buildAuthorizationUrl(config, params);

      // Redirect to the authorization endpoint
      res.redirect(authUrl.href);
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /device/start - Initiate Device Authorization Grant
   */
  router.post('/device/start', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { issuer, clientId, clientSecret, scope } = req.body;

      // Discover the OIDC provider
      const config = await client.discovery(
        new URL(issuer),
        clientId,
        clientSecret || undefined,
        clientSecret ? client.ClientSecretBasic(clientSecret) : undefined,
        { execute: [client.allowInsecureRequests] }
      );

      // Initiate device authorization
      const deviceAuthResponse = await client.initiateDeviceAuthorization(
        config,
        { scope }
      );

      // Store in session for polling
      req.session.deviceAuthResponse = {
        device_code: deviceAuthResponse.device_code,
        user_code: deviceAuthResponse.user_code,
        verification_uri: deviceAuthResponse.verification_uri,
        verification_uri_complete: deviceAuthResponse.verification_uri_complete,
        expires_in: deviceAuthResponse.expires_in,
        interval: deviceAuthResponse.interval,
      };
      req.session.flowConfig = { issuer, clientId, clientSecret };

      // Save to flow history
      flowConfigRepo.createFlowConfig(getDb(), {
        issuer,
        clientId,
        clientSecret,
        responseType: 'device_code',
        scope,
        redirectUri: '',
        pkceEnabled: false,
        stateEnabled: false,
        nonceEnabled: false,
      });

      res.render('flow/device', {
        title: 'Device Flow',
        activeNav: 'flow',
        userCode: deviceAuthResponse.user_code,
        verificationUri: deviceAuthResponse.verification_uri,
        verificationUriComplete: deviceAuthResponse.verification_uri_complete,
        expiresIn: deviceAuthResponse.expires_in,
        interval: deviceAuthResponse.interval || 5,
        issuer,
        clientId,
        clientSecret,
      });
    } catch (err: unknown) {
      const error = err as Error & {
        error?: string;
        error_description?: string;
        cause?: Error & { error?: string; error_description?: string };
      };
      console.error('[DEVICE/START] Error:', error);

      // openid-client v6 wraps server errors — dig into .cause for the real OAuth error
      const oauthError = error.cause?.error ? error.cause : error;
      let message: string;

      if ((oauthError as any).error_description) {
        message = `${(oauthError as any).error}: ${(oauthError as any).error_description}`;
      } else if ((oauthError as any).error) {
        message = (oauthError as any).error;
      } else {
        message = error.message;
      }

      // Add a helpful hint for the most common device flow error
      if (message.includes('not allowed for this client')) {
        message += '\n\nHint: Your client needs the "urn:ietf:params:oauth:grant-type:device_code" grant type. '
          + 'Create a new client using the "Device Flow Client" preset in the admin dashboard, or update your existing client\'s grant types.';
      }

      res.render('error', {
        title: 'Device Flow Error',
        activeNav: 'flow',
        error: message,
        errorStack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      });
    }
  });

  /**
   * GET /device/status - Lightweight poll to check if device code has been authorized
   * Returns JSON: { status: "pending" | "authorized" | "slow_down" | "expired" | "error", message?: string }
   */
  router.get('/device/status', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const deviceAuthResponse = req.session.deviceAuthResponse;
      const flowConfig = req.session.flowConfig;

      if (!deviceAuthResponse || !flowConfig) {
        return res.json({ status: 'error', message: 'No device flow in progress. Session may have expired.' });
      }

      const { issuer, clientId, clientSecret } = flowConfig;

      // Discover the OIDC provider
      const config = await client.discovery(
        new URL(issuer),
        clientId,
        clientSecret || undefined,
        clientSecret ? client.ClientSecretBasic(clientSecret) : undefined,
        { execute: [client.allowInsecureRequests] }
      );

      // Make a single token request (non-blocking) to check authorization status
      try {
        const tokenResponse = await client.genericGrantRequest(
          config,
          'urn:ietf:params:oauth:grant-type:device_code',
          { device_code: deviceAuthResponse.device_code },
        );
        // Success — device code is now consumed (one-time use).
        // Save the tokens in session so /device/exchange can use them
        // without making another token request (which would fail with "already consumed").
        req.session.deviceTokenResponse = {
          access_token: tokenResponse.access_token,
          id_token: tokenResponse.id_token,
          refresh_token: tokenResponse.refresh_token,
          token_type: tokenResponse.token_type,
          expires_in: tokenResponse.expires_in,
          scope: tokenResponse.scope as string | undefined,
        };
        // Ensure session is persisted before responding — the next request
        // (POST /device/exchange) needs these tokens immediately.
        await new Promise<void>((resolve, reject) =>
          req.session.save((err) => (err ? reject(err) : resolve()))
        );
        return res.json({ status: 'authorized' });
      } catch (err) {
        if (err instanceof client.ResponseBodyError) {
          switch (err.error) {
            case 'authorization_pending':
              return res.json({ status: 'pending' });
            case 'slow_down':
              return res.json({ status: 'slow_down' });
            case 'expired_token':
              return res.json({ status: 'expired' });
            case 'access_denied':
              return res.json({ status: 'expired', message: 'Access denied by user.' });
            default:
              return res.json({ status: 'error', message: err.error_description || err.error });
          }
        }
        throw err;
      }
    } catch (err: unknown) {
      const error = err as Error;
      console.error('[DEVICE/STATUS] Error:', error);
      return res.json({ status: 'error', message: error.message });
    }
  });

  /**
   * POST /device/exchange - Display the tokens obtained during polling
   * The polling endpoint (GET /device/status) already exchanged the device code for tokens
   * and saved them in the session. This route retrieves them, decodes/introspects, and renders.
   */
  router.post('/device/exchange', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const savedTokens = req.session.deviceTokenResponse;
      const flowConfig = req.session.flowConfig;

      if (!savedTokens || !flowConfig) {
        return res.render('error', {
          title: 'Device Exchange Error',
          activeNav: 'flow',
          error: 'No device tokens available. The polling endpoint may not have captured them, or the session expired.',
        });
      }

      const { issuer, clientId, clientSecret } = flowConfig;

      // Get the tokens from the session (already obtained during polling)
      const accessToken = savedTokens.access_token;
      const idToken = savedTokens.id_token;
      const refreshToken = savedTokens.refresh_token;
      const tokenType = savedTokens.token_type;
      const expiresIn = savedTokens.expires_in;

      // Discover the OIDC provider (needed for introspection/userinfo)
      const config = await client.discovery(
        new URL(issuer),
        clientId,
        clientSecret || undefined,
        clientSecret ? client.ClientSecretBasic(clientSecret) : undefined,
        { execute: [client.allowInsecureRequests] }
      );

      // Decode the ID token
      let idTokenDecoded: { header: unknown; payload: unknown } | undefined;
      if (idToken) {
        const parts = idToken.split('.');
        if (parts.length === 3) {
          idTokenDecoded = {
            header: JSON.parse(Buffer.from(parts[0], 'base64url').toString()),
            payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString()),
          };
        }
      }

      // Introspect the access token
      let introspectionResult: unknown;
      try {
        if (accessToken && config.serverMetadata().introspection_endpoint) {
          introspectionResult = await client.tokenIntrospection(config, accessToken);
        }
      } catch (err) {
        console.error('[DEVICE/EXCHANGE] Introspection failed:', err);
      }

      // Get userinfo
      let userinfoResult: unknown;
      try {
        if (accessToken && config.serverMetadata().userinfo_endpoint) {
          const expectedSub = (idTokenDecoded?.payload as any)?.sub || client.skipSubjectCheck;
          userinfoResult = await client.fetchUserInfo(config, accessToken, expectedSub);
        }
      } catch (err) {
        console.error('[DEVICE/EXCHANGE] UserInfo failed:', err);
      }

      // Clean up session
      delete req.session.deviceAuthResponse;
      delete req.session.deviceTokenResponse;

      res.render('flow/callback', {
        title: 'Device Flow — Token Response',
        activeNav: 'flow',
        tokens: {
          accessToken,
          idToken,
          refreshToken,
          tokenType,
          expiresIn,
        },
        idTokenDecoded,
        introspection: introspectionResult,
        userinfo: userinfoResult,
        issuer,
        clientId,
        clientSecret,
      });
    } catch (err: unknown) {
      const error = err as Error & {
        error?: string;
        error_description?: string;
        cause?: unknown;
      };
      console.error('[DEVICE/EXCHANGE] Error:', error);

      const message = error.error_description
        ? `${error.error}: ${error.error_description}`
        : error.message;

      res.render('flow/callback', {
        title: 'Device Flow Error',
        activeNav: 'flow',
        error: message,
        errorStack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      });
    }
  });

  /**
   * GET /callback - Handle the authorization response
   */
  router.get('/callback', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { issuer, clientId, clientSecret } = req.session.flowConfig || {};

      if (!issuer || !clientId) {
        return res.render('flow/callback', {
          title: 'Callback Error',
          activeNav: 'flow',
          error: 'No flow in progress. Session may have expired.',
        });
      }

      // Check for error response
      if (req.query.error) {
        return res.render('flow/callback', {
          title: 'Authorization Error',
          activeNav: 'flow',
          error: req.query.error,
          errorDescription: req.query.error_description,
        });
      }

      // Discover the provider (allow HTTP for localhost dev)
      const config = await client.discovery(
        new URL(issuer),
        clientId,
        clientSecret || undefined,
        clientSecret ? client.ClientSecretBasic(clientSecret) : undefined,
        { execute: [client.allowInsecureRequests] }
      );

      // Build the callback URL using ISSUER as base to preserve the correct
      // scheme in deployed environments where a reverse proxy terminates TLS.
      // Using req.headers.host with hardcoded 'http://' would produce an http://
      // URL even when the public-facing URL is https://, causing a redirect_uri
      // mismatch in the token exchange (invalid_grant).
      const currentUrl = new URL(req.originalUrl, ISSUER);

      // Exchange the code for tokens
      console.log('[CALLBACK] Calling authorizationCodeGrant...');
      const tokenResponse = await client.authorizationCodeGrant(config, currentUrl, {
        pkceCodeVerifier: req.session.pkceCodeVerifier,
        expectedState: req.session.state,
        expectedNonce: req.session.nonce,
        idTokenExpected: true,
      });
      console.log('[CALLBACK] authorizationCodeGrant succeeded');

      // Get the tokens
      const accessToken = tokenResponse.access_token;
      const idToken = tokenResponse.id_token;
      const refreshToken = tokenResponse.refresh_token;
      const tokenType = tokenResponse.token_type;
      const expiresIn = tokenResponse.expires_in;

      // Decode the ID token
      let idTokenDecoded: { header: unknown; payload: unknown } | undefined;
      if (idToken) {
        const parts = idToken.split('.');
        if (parts.length === 3) {
          idTokenDecoded = {
            header: JSON.parse(Buffer.from(parts[0], 'base64url').toString()),
            payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString()),
          };
        }
      }

      // Introspect the access token (if supported)
      let introspectionResult: unknown;
      try {
        if (accessToken && config.serverMetadata().introspection_endpoint) {
          console.log('[CALLBACK] Calling tokenIntrospection...');
          introspectionResult = await client.tokenIntrospection(config, accessToken);
          console.log('[CALLBACK] tokenIntrospection succeeded');
        }
      } catch (err) {
        console.error('[CALLBACK] tokenIntrospection FAILED:', err);
      }

      // Get userinfo (if supported)
      let userinfoResult: unknown;
      try {
        if (accessToken && config.serverMetadata().userinfo_endpoint) {
          console.log('[CALLBACK] Calling fetchUserInfo...');
          const expectedSub = (idTokenDecoded?.payload as any)?.sub || client.skipSubjectCheck;
          userinfoResult = await client.fetchUserInfo(config, accessToken, expectedSub);
          console.log('[CALLBACK] fetchUserInfo succeeded');
        }
      } catch (err) {
        console.error('[CALLBACK] fetchUserInfo FAILED:', err);
      }

      // Clear session (keep flowConfig if we have a refresh token for later use)
      delete req.session.pkceCodeVerifier;
      delete req.session.state;
      delete req.session.nonce;
      if (!refreshToken) {
        delete req.session.flowConfig;
      }

      res.render('flow/callback', {
        title: 'Token Response',
        activeNav: 'flow',
        tokens: {
          accessToken,
          idToken,
          refreshToken,
          tokenType,
          expiresIn,
        },
        idTokenDecoded,
        introspection: introspectionResult,
        userinfo: userinfoResult,
        issuer,
        clientId,
        clientSecret,
      });
    } catch (err: unknown) {
      const error = err as Error & {
        error?: string;
        error_description?: string;
        status?: number;
        cause?: unknown;
      };
      console.error('[CALLBACK] OUTER catch - error reached error page:', error);
      console.error('[CALLBACK] Error name:', error.name);
      console.error('[CALLBACK] Error message:', error.message);
      console.error('[CALLBACK] OAuth error:', error.error);
      console.error('[CALLBACK] OAuth error_description:', error.error_description);
      console.error('[CALLBACK] OAuth cause:', error.cause);

      const message = error.error_description
        ? `${error.error}: ${error.error_description}`
        : error.message;

      res.render('flow/callback', {
        title: 'Callback Error',
        activeNav: 'flow',
        error: message,
        errorStack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      });
    }
  });

  /**
   * POST /refresh - Exchange a refresh token for new tokens
   */
  router.post('/refresh', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { refreshToken, issuer, clientId, clientSecret } = req.body;

      if (!refreshToken || !issuer || !clientId) {
        return res.render('flow/callback', {
          title: 'Refresh Error',
          activeNav: 'flow',
          error: 'Missing refresh token or client configuration.',
        });
      }

      // Discover the provider (allow HTTP for localhost dev)
      const config = await client.discovery(
        new URL(issuer),
        clientId,
        clientSecret || undefined,
        clientSecret ? client.ClientSecretBasic(clientSecret) : undefined,
        { execute: [client.allowInsecureRequests] }
      );

      // Exchange the refresh token
      const tokenResponse = await client.refreshTokenGrant(config, refreshToken);

      // Get the new tokens
      const newAccessToken = tokenResponse.access_token;
      const newIdToken = tokenResponse.id_token;
      const newRefreshToken = tokenResponse.refresh_token;
      const tokenType = tokenResponse.token_type;
      const expiresIn = tokenResponse.expires_in;

      // Decode the new ID token
      let idTokenDecoded: { header: unknown; payload: unknown } | undefined;
      if (newIdToken) {
        const parts = newIdToken.split('.');
        if (parts.length === 3) {
          idTokenDecoded = {
            header: JSON.parse(Buffer.from(parts[0], 'base64url').toString()),
            payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString()),
          };
        }
      }

      // Introspect the new access token
      let introspectionResult: unknown;
      try {
        if (newAccessToken && config.serverMetadata().introspection_endpoint) {
          introspectionResult = await client.tokenIntrospection(config, newAccessToken);
        }
      } catch (err) {
        console.error('Introspection failed:', err);
      }

      // Get userinfo with new token
      let userinfoResult: unknown;
      try {
        if (newAccessToken && config.serverMetadata().userinfo_endpoint) {
          const expectedSub = (idTokenDecoded?.payload as any)?.sub || client.skipSubjectCheck;
          userinfoResult = await client.fetchUserInfo(config, newAccessToken, expectedSub);
        }
      } catch (err) {
        console.error('UserInfo failed:', err);
      }

      res.render('flow/callback', {
        title: 'Refreshed Token Response',
        activeNav: 'flow',
        tokens: {
          accessToken: newAccessToken,
          idToken: newIdToken,
          refreshToken: newRefreshToken || refreshToken,
          tokenType,
          expiresIn,
        },
        idTokenDecoded,
        introspection: introspectionResult,
        userinfo: userinfoResult,
        issuer,
        clientId,
        clientSecret,
        wasRefreshed: true,
      });
    } catch (err: unknown) {
      const error = err as Error & {
        error?: string;
        error_description?: string;
        cause?: unknown;
      };
      console.error('Refresh error:', error);
      console.error('OAuth error:', error.error);
      console.error('OAuth error_description:', error.error_description);

      const message = error.error_description
        ? `${error.error}: ${error.error_description}`
        : error.message;

      res.render('flow/callback', {
        title: 'Refresh Error',
        activeNav: 'flow',
        error: message,
        errorStack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      });
    }
  });

  /**
   * POST /introspect - Re-introspect the access token on demand
   */
  router.post('/introspect', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { accessToken, idToken, refreshToken, issuer, clientId, clientSecret } = req.body;

      if (!accessToken || !issuer || !clientId) {
        return res.render('flow/callback', {
          title: 'Introspection Error',
          activeNav: 'flow',
          error: 'Missing access token or client configuration.',
        });
      }

      // Discover the provider (allow HTTP for localhost dev)
      const config = await client.discovery(
        new URL(issuer),
        clientId,
        clientSecret || undefined,
        clientSecret ? client.ClientSecretBasic(clientSecret) : undefined,
        { execute: [client.allowInsecureRequests] }
      );

      // Introspect the access token
      let introspectionResult: unknown;
      try {
        console.log('[INTROSPECT] Calling tokenIntrospection...');
        introspectionResult = await client.tokenIntrospection(config, accessToken);
        console.log('[INTROSPECT] tokenIntrospection succeeded');
      } catch (err) {
        console.error('[INTROSPECT] tokenIntrospection FAILED:', err);
        introspectionResult = { error: (err as Error).message };
      }

      // Decode the ID token if present
      let idTokenDecoded: { header: unknown; payload: unknown } | undefined;
      if (idToken) {
        const parts = idToken.split('.');
        if (parts.length === 3) {
          idTokenDecoded = {
            header: JSON.parse(Buffer.from(parts[0], 'base64url').toString()),
            payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString()),
          };
        }
      }

      // Get userinfo if we have a valid access token
      let userinfoResult: unknown;
      try {
        if (accessToken && config.serverMetadata().userinfo_endpoint && introspectionResult && (introspectionResult as any).active) {
          console.log('[INTROSPECT] Calling fetchUserInfo...');
          const expectedSub = (idTokenDecoded?.payload as any)?.sub || client.skipSubjectCheck;
          userinfoResult = await client.fetchUserInfo(config, accessToken, expectedSub);
          console.log('[INTROSPECT] fetchUserInfo succeeded');
        }
      } catch (err) {
        console.error('[INTROSPECT] fetchUserInfo FAILED:', err);
      }

      res.render('flow/callback', {
        title: 'Token Response',
        activeNav: 'flow',
        tokens: {
          accessToken,
          idToken,
          refreshToken,
        },
        idTokenDecoded,
        introspection: introspectionResult,
        userinfo: userinfoResult,
        issuer,
        clientId,
        clientSecret,
      });
    } catch (err: unknown) {
      const error = err as Error & { error_description?: string };
      console.error('[INTROSPECT] OUTER catch:', error);
      res.render('flow/callback', {
        title: 'Introspection Error',
        activeNav: 'flow',
        error: error.error_description || error.message,
      });
    }
  });

  /**
   * POST /revoke - Revoke the access and/or refresh tokens
   */
  router.post('/revoke', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { accessToken, idToken, refreshToken, issuer, clientId, clientSecret } = req.body;

      if (!issuer || !clientId) {
        return res.render('flow/callback', {
          title: 'Revocation Error',
          activeNav: 'flow',
          error: 'Missing client configuration.',
        });
      }

      // Discover the provider (allow HTTP for localhost dev)
      const config = await client.discovery(
        new URL(issuer),
        clientId,
        clientSecret || undefined,
        clientSecret ? client.ClientSecretBasic(clientSecret) : undefined,
        { execute: [client.allowInsecureRequests] }
      );

      // Revoke access token if present
      if (accessToken) {
        try {
          console.log('[REVOKE] Revoking access token...');
          await client.tokenRevocation(config, accessToken, { token_type_hint: 'access_token' });
          console.log('[REVOKE] Access token revoked');
        } catch (err) {
          console.error('[REVOKE] Access token revocation failed:', err);
        }
      }

      // Revoke refresh token if present
      if (refreshToken) {
        try {
          console.log('[REVOKE] Revoking refresh token...');
          await client.tokenRevocation(config, refreshToken, { token_type_hint: 'refresh_token' });
          console.log('[REVOKE] Refresh token revoked');
        } catch (err) {
          console.error('[REVOKE] Refresh token revocation failed:', err);
        }
      }

      // Decode the ID token if present
      let idTokenDecoded: { header: unknown; payload: unknown } | undefined;
      if (idToken) {
        const parts = idToken.split('.');
        if (parts.length === 3) {
          idTokenDecoded = {
            header: JSON.parse(Buffer.from(parts[0], 'base64url').toString()),
            payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString()),
          };
        }
      }

      res.render('flow/callback', {
        title: 'Token Response',
        activeNav: 'flow',
        tokens: {
          accessToken,
          idToken,
          refreshToken,
        },
        idTokenDecoded,
        introspection: null,
        userinfo: null,
        issuer,
        clientId,
        clientSecret,
        revoked: true,
      });
    } catch (err: unknown) {
      const error = err as Error & { error_description?: string };
      console.error('[REVOKE] OUTER catch:', error);
      res.render('flow/callback', {
        title: 'Revocation Error',
        activeNav: 'flow',
        error: error.error_description || error.message,
      });
    }
  });

  /**
   * POST /end-session - RP-Initiated Logout (end the OP session)
   */
  router.post('/end-session', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { idToken, issuer, clientId, clientSecret } = req.body;

      if (!issuer || !clientId) {
        return res.redirect('/flow?error=missing_config');
      }

      // Discover the provider (allow HTTP for localhost dev)
      const config = await client.discovery(
        new URL(issuer),
        clientId,
        clientSecret || undefined,
        clientSecret ? client.ClientSecretBasic(clientSecret) : undefined,
        { execute: [client.allowInsecureRequests] }
      );

      // Check if end_session_endpoint is available
      const endSessionEndpoint = config.serverMetadata().end_session_endpoint;
      if (!endSessionEndpoint) {
        return res.render('flow/callback', {
          title: 'End Session Error',
          activeNav: 'flow',
          error: 'The authorization server does not support end_session_endpoint.',
        });
      }

      // Build the end session URL
      const endSessionUrl = client.buildEndSessionUrl(config, {
        id_token_hint: idToken,
        post_logout_redirect_uri: `${ISSUER}/flow`,
      });

      // Clear the session
      req.session.destroy((err) => {
        if (err) {
          console.error('[END-SESSION] Session destroy error:', err);
        }
        // Redirect to the OP end session endpoint
        res.redirect(endSessionUrl.toString());
      });
    } catch (err: unknown) {
      const error = err as Error & { error_description?: string };
      console.error('[END-SESSION] OUTER catch:', error);
      res.render('flow/callback', {
        title: 'End Session Error',
        activeNav: 'flow',
        error: error.error_description || error.message,
      });
    }
  });

  /**
   * POST /local-logout - Clear only the client session (OP session stays alive)
   */
  router.post('/local-logout', (req: Request, res: Response) => {
    req.session.destroy((err) => {
      if (err) {
        console.error('[LOCAL-LOGOUT] Session destroy error:', err);
      }
      res.redirect('/flow?logged_out=true');
    });
  });

  /**
   * GET /history/:id - Load a flow config into the form
   */
  router.get('/history/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const flowConfig = flowConfigRepo.findFlowConfigById(getDb(), req.params.id);

      if (!flowConfig) {
        return res.redirect('/flow');
      }

      const recentFlows = flowConfigRepo.listRecentFlowConfigs(getDb(), 10);

      res.render('flow/index', {
        title: 'Flow Starter',
        activeNav: 'flow',
        presets: FLOW_PRESETS,
        defaults: {
          issuer: flowConfig.issuer,
          clientId: flowConfig.clientId,
          clientSecret: flowConfig.clientSecret,
          redirectUri: flowConfig.redirectUri,
          responseType: flowConfig.responseType,
          scope: flowConfig.scope,
          pkceEnabled: flowConfig.pkceEnabled,
          stateEnabled: flowConfig.stateEnabled,
          nonceEnabled: flowConfig.nonceEnabled,
          extraParams: flowConfig.extraParams
            ? JSON.stringify(flowConfig.extraParams)
            : '',
        },
        recentFlows,
        loadedFromHistory: true,
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

export default createFlowRouter;
