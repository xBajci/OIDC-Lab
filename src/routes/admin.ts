import { Router } from 'express';
import Provider from 'oidc-provider';
import { getDb } from '../db.js';
import * as userRepo from '../repos/users.js';
import * as oidcRepo from '../repos/oidc-documents.js';
import * as credRepo from '../repos/client-credentials.js';

// Helper to list all oidc_documents by model (not exposed by repo)
interface OidcDocumentRow {
  key: string;
  model: string;
  payload: string;
  expires_at: number | null;
  consumed_at: number | null;
  user_code: string | null;
  uid: string | null;
  grant_id: string | null;
}

function listDocumentsByModel(model: string) {
  const rows = getDb()
    .query("SELECT * FROM oidc_documents WHERE model = ?")
    .all(model) as OidcDocumentRow[];

  return rows.map((row) => ({
    key: row.key,
    model: row.model,
    payload: JSON.parse(row.payload) as Record<string, unknown>,
    expiresAt: row.expires_at,
    consumedAt: row.consumed_at,
    userCode: row.user_code,
    uid: row.uid,
    grantId: row.grant_id,
  }));
}

// Client presets for Dynamic Client Registration
const CLIENT_PRESETS = {
  confidential: {
    name: 'Confidential Client (Server-Side App)',
    tooltip:
      'A client with a backend that can securely store a client_secret. Authenticates to the token endpoint using the secret (sent as HTTP Basic auth header). Can exchange authorization codes and refresh tokens. This is the most common type for server-rendered web apps.',
    config: {
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: 'openid profile email',
      application_type: 'web',
    },
  },
  public: {
    name: 'Public Client (SPA / Native App)',
    tooltip:
      "A client that cannot keep secrets - like a JavaScript SPA or mobile app. No client_secret is issued. The client relies on PKCE for security during the code exchange instead of authenticating with a secret. No refresh_token grant because rotating refresh tokens in a public client is complex.",
    config: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      scope: 'openid profile email',
      application_type: 'web',
    },
  },
  implicit: {
    name: 'Implicit Client (Legacy SPA)',
    tooltip:
      "A legacy client configuration for the implicit flow. Tokens are returned directly in the URL fragment - no code exchange happens, so there's no token endpoint auth. This pattern is deprecated by OAuth 2.1 in favor of public clients using authorization code + PKCE.",
    config: {
      grant_types: ['implicit'],
      response_types: ['id_token', 'id_token token'],
      token_endpoint_auth_method: 'none',
      scope: 'openid profile email',
      application_type: 'web',
    },
  },
  secure: {
    name: 'Most Secure (Confidential + Strict)',
    tooltip:
      "Maximum security: authorization code only (no implicit, no refresh tokens unless explicitly needed), confidential client authentication, minimal scope. No refresh_token grant means the user must re-authenticate when the access token expires - more secure but less convenient.",
    config: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: 'openid',
      application_type: 'web',
    },
  },
  device: {
    name: 'Device Flow Client (TV / CLI)',
    tooltip:
      'A client for devices with limited input capabilities (smart TVs, CLI tools, IoT devices). The device displays a code and URL, and the user authorizes on a separate device with a browser. Uses the Device Authorization Grant (RFC 8628). Confidential client with client_secret_basic authentication.',
    config: {
      grant_types: ['urn:ietf:params:oauth:grant-type:device_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: 'openid profile email',
      application_type: 'native',
    },
  },
};

export function createAdminRouter(provider: Provider): Router {
  const router = Router();

  // ==================== Dashboard ====================

  router.get('/', async (req, res, next) => {
    try {
      const userCount = userRepo.countUsers(getDb());

      res.render('admin/dashboard', {
        title: 'Admin Dashboard',
        activeNav: 'dashboard',
        userCount,
        issuer: process.env.ISSUER || 'http://localhost:3000',
      });
    } catch (err) {
      next(err);
    }
  });

  // ==================== Users ====================

  router.get('/users', async (req, res, next) => {
    try {
      const users = userRepo.listUsers(getDb());
      res.render('admin/users/list', {
        title: 'Users',
        activeNav: 'users',
        users,
      });
    } catch (err) {
      next(err);
    }
  });

  router.get('/users/new', (req, res) => {
    res.render('admin/users/form', {
      title: 'New User',
      activeNav: 'users',
      user: {},
      isNew: true,
    });
  });

  router.post('/users', async (req, res, next) => {
    try {
      const { username, password, email, name, roles, emailVerified } = req.body;

      await userRepo.createUser(getDb(), {
        username,
        password,
        email: email || undefined,
        name: name || undefined,
        roles: roles ? roles.split(',').map((r: string) => r.trim()) : ['user'],
        emailVerified: emailVerified === 'on',
      });

      res.redirect('/admin/users');
    } catch (err: unknown) {
      const error = err as Error;
      if (error.message?.includes('already taken')) {
        return res.render('admin/users/form', {
          title: 'New User',
          activeNav: 'users',
          user: req.body,
          isNew: true,
          error: 'Username already exists',
        });
      }
      next(err);
    }
  });

  router.get('/users/:id/edit', async (req, res, next) => {
    try {
      const user = userRepo.findUserById(getDb(), req.params.id);
      if (!user) {
        return res.status(404).render('error', {
          title: 'Not Found',
          error: 'User not found',
        });
      }
      res.render('admin/users/form', {
        title: 'Edit User',
        activeNav: 'users',
        user: {
          ...user,
          roles: user.roles.join(', '),
        },
        isNew: false,
      });
    } catch (err) {
      next(err);
    }
  });

  router.post('/users/:id', async (req, res, next) => {
    try {
      const { username, password, email, name, roles, emailVerified } = req.body;

      const updateData: Parameters<typeof userRepo.updateUser>[2] = {
        username,
        email: email || undefined,
        name: name || undefined,
        roles: roles ? roles.split(',').map((r: string) => r.trim()) : ['user'],
        emailVerified: emailVerified === 'on',
      };

      // Only update password if provided
      if (password) {
        updateData.password = password;
      }

      const updated = await userRepo.updateUser(getDb(), req.params.id, updateData);

      if (!updated) {
        return res.status(404).render('error', {
          title: 'Not Found',
          error: 'User not found',
        });
      }

      res.redirect('/admin/users');
    } catch (err: unknown) {
      const error = err as Error;
      if (error.message?.includes('already taken') || error.message?.includes('UNIQUE constraint failed')) {
        return res.render('admin/users/form', {
          title: 'Edit User',
          activeNav: 'users',
          user: { ...req.body, id: req.params.id },
          isNew: false,
          error: 'Username already exists',
        });
      }
      next(err);
    }
  });

  router.post('/users/:id/delete', async (req, res, next) => {
    try {
      userRepo.deleteUser(getDb(), req.params.id);
      res.redirect('/admin/users');
    } catch (err) {
      next(err);
    }
  });

  // ==================== Clients ====================

  router.get('/clients', async (req, res, next) => {
    try {
      const clients = listDocumentsByModel('Client');

      const clientList = clients.map((c) => ({
        client_id: (c.payload?.client_id as string) || c.key,
        client_name: (c.payload?.client_name as string) || 'Unnamed Client',
        grant_types: (c.payload?.grant_types as string[]) || [],
        response_types: (c.payload?.response_types as string[]) || [],
        token_endpoint_auth_method: c.payload?.token_endpoint_auth_method as string,
      }));

      res.render('admin/clients/list', {
        title: 'Clients',
        activeNav: 'clients',
        clients: clientList,
      });
    } catch (err) {
      next(err);
    }
  });

  router.get('/clients/new', (req, res) => {
    const serverUrl = process.env.ISSUER || 'http://localhost:3000';
    res.render('admin/clients/form', {
      title: 'Register Client',
      activeNav: 'clients',
      presets: CLIENT_PRESETS,
      defaults: {
        redirect_uris: `${serverUrl}/flow/callback`,
        grant_types: 'authorization_code',
        response_types: 'code',
        scope: 'openid profile email',
        token_endpoint_auth_method: 'client_secret_basic',
        application_type: 'web',
      },
    });
  });

  router.post('/clients', async (req, res, next) => {
    try {
      const {
        client_name,
        redirect_uris,
        post_logout_redirect_uris,
        grant_types,
        response_types,
        scope,
        token_endpoint_auth_method,
        application_type,
      } = req.body;

      // Build client metadata
      const clientMetadata = {
        client_name,
        redirect_uris: redirect_uris
          .split('\n')
          .map((u: string) => u.trim())
          .filter(Boolean),
        post_logout_redirect_uris: post_logout_redirect_uris
          ? post_logout_redirect_uris
              .split('\n')
              .map((u: string) => u.trim())
              .filter(Boolean)
          : undefined,
        grant_types: grant_types
          .split(',')
          .map((g: string) => g.trim())
          .filter(Boolean),
        response_types: response_types
          .split(',')
          .map((r: string) => r.trim())
          .filter(Boolean),
        scope,
        token_endpoint_auth_method,
        application_type,
      };

      // Call the /reg endpoint internally
      const issuer = process.env.ISSUER || 'http://localhost:3000';
      const response = await fetch(`${issuer}/reg`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(clientMetadata),
      });

      const result = await response.json();

      if (!response.ok) {
        return res.render('admin/clients/form', {
          title: 'Register Client',
          activeNav: 'clients',
          presets: CLIENT_PRESETS,
          defaults: req.body,
          error: result.error_description || result.error || 'Registration failed',
        });
      }

      // Store plaintext credentials (oidc-provider hashes the secret)
      credRepo.upsertCredentials(getDb(), result.client_id, result.client_secret || '');

      res.render('admin/clients/created', {
        title: 'Client Created',
        activeNav: 'clients',
        client: result,
      });
    } catch (err) {
      next(err);
    }
  });

  router.get('/clients/:id', async (req, res, next) => {
    try {
      const doc = oidcRepo.findDocument(getDb(), req.params.id, 'Client');

      if (!doc) {
        return res.status(404).render('error', {
          title: 'Not Found',
          error: 'Client not found',
        });
      }

      // Look up stored plaintext credentials
      const cred = credRepo.findCredentials(getDb(), req.params.id);

      // Map to snake_case for template compatibility
      const credentials = cred
        ? {
            client_id: cred.clientId,
            client_secret: cred.clientSecret,
          }
        : null;

      res.render('admin/clients/show', {
        title: (doc.payload?.client_name as string) || 'Client Details',
        activeNav: 'clients',
        client: doc.payload,
        credentials,
      });
    } catch (err) {
      next(err);
    }
  });

  router.post('/clients/:id/delete', async (req, res, next) => {
    try {
      oidcRepo.destroyDocument(getDb(), req.params.id, 'Client');
      credRepo.deleteCredentials(getDb(), req.params.id);

      res.redirect('/admin/clients');
    } catch (err) {
      next(err);
    }
  });

  // ==================== Client API (JSON) ====================

  /**
   * GET /admin/api/clients - List all clients with their plaintext credentials
   * Used by the flow starter to populate the client dropdown.
   * Returns JSON array of { client_id, client_name, client_secret, grant_types, scope }.
   * CORS header included for external consumers.
   */
  router.get('/api/clients', async (req, res, next) => {
    try {
      // Allow cross-origin requests from the client app
      res.set('Access-Control-Allow-Origin', '*');

      const clients = listDocumentsByModel('Client');
      const credentials = credRepo.listCredentials(getDb());

      // Index credentials by client_id for fast lookup
      const credMap = new Map(credentials.map((c) => [c.clientId, c]));

      const result = clients.map((c) => {
        const clientId = (c.payload?.client_id as string) || c.key;
        const cred = credMap.get(clientId);
        return {
          client_id: clientId,
          client_name: (c.payload?.client_name as string) || 'Unnamed Client',
          client_secret: cred?.clientSecret || null,
          grant_types: (c.payload?.grant_types as string[]) || [],
          response_types: (c.payload?.response_types as string[]) || [],
          scope: (c.payload?.scope as string) || '',
          token_endpoint_auth_method: (c.payload?.token_endpoint_auth_method as string) || 'client_secret_basic',
        };
      });

      res.json(result);
    } catch (err) {
      next(err);
    }
  });

  return router;
}

export default createAdminRouter;
