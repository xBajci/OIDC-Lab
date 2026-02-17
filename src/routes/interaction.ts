import { Router } from 'express';
import Provider, { InteractionResults } from 'oidc-provider';
import { getDb } from '../db.js';
import * as userRepo from '../repos/users.js';

export function createInteractionRouter(provider: Provider): Router {
  const router = Router();

  /**
   * GET /interaction/:uid
   * Display the appropriate interaction page (login or consent)
   */
  router.get('/:uid', async (req, res, next) => {
    try {
      const { uid, prompt, params, session } = await provider.interactionDetails(
        req,
        res
      );

      const client = await provider.Client.find(params.client_id as string);

      switch (prompt.name) {
        case 'login': {
          return res.render('interaction/login', {
            title: 'Sign In',
            uid,
            client: {
              name: client?.clientName || params.client_id,
              id: params.client_id,
            },
            params: {
              login_hint: params.login_hint,
            },
            flash: req.query.error ? { error: req.query.error } : undefined,
            layout: 'interaction',
          });
        }

        case 'consent': {
          const missingOIDCScope = new Set(
            (prompt.details.missingOIDCScope as string[]) || []
          );
          const missingResourceScopes = prompt.details.missingResourceScopes || {};

          // Get the scopes that need to be consented
          const scopesRequested = (params.scope as string)?.split(' ') || [];

          return res.render('interaction/consent', {
            title: 'Authorize',
            uid,
            client: {
              name: client?.clientName || params.client_id,
              id: params.client_id,
            },
            scopes: scopesRequested.filter((s) => s !== 'openid'),
            missingOIDCScope: Array.from(missingOIDCScope),
            session: session
              ? {
                  accountId: session.accountId,
                }
              : undefined,
            layout: 'interaction',
          });
        }

        default:
          return res.status(501).render('error', {
            title: 'Error',
            error: `Unknown prompt type: ${prompt.name}`,
            layout: 'interaction',
          });
      }
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /interaction/:uid/login
   * Handle login form submission
   */
  router.post('/:uid/login', async (req, res, next) => {
    try {
      const { uid } = req.params;
      const { username, password } = req.body;

      // Validate input
      if (!username || !password) {
        return res.redirect(`/interaction/${uid}?error=Please+enter+username+and+password`);
      }

      // Find user
      const user = userRepo.findUserByUsername(getDb(), username);

      if (!user) {
        return res.redirect(`/interaction/${uid}?error=Invalid+username+or+password`);
      }

      // Verify password
      const isValid = await userRepo.comparePassword(getDb(), user.id, password);

      if (!isValid) {
        return res.redirect(`/interaction/${uid}?error=Invalid+username+or+password`);
      }

      // Finish login interaction
      const result: InteractionResults = {
        login: {
          accountId: user.id,
        },
      };

      await provider.interactionFinished(req, res, result, {
        mergeWithLastSubmission: false,
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /interaction/:uid/confirm
   * Handle consent form submission (approve)
   */
  router.post('/:uid/confirm', async (req, res, next) => {
    try {
      const interactionDetails = await provider.interactionDetails(req, res);
      const {
        prompt: { name, details },
        params,
        session,
      } = interactionDetails;

      if (name !== 'consent') {
        return res.status(400).render('error', {
          title: 'Error',
          error: 'Invalid interaction state',
          layout: 'interaction',
        });
      }

      // Create a grant for this consent
      let grant = interactionDetails.grantId
        ? await provider.Grant.find(interactionDetails.grantId)
        : new provider.Grant({
            accountId: session?.accountId,
            clientId: params.client_id as string,
          });

      if (!grant) {
        grant = new provider.Grant({
          accountId: session?.accountId,
          clientId: params.client_id as string,
        });
      }

      // Add OIDC scopes
      if (details.missingOIDCScope) {
        grant.addOIDCScope((details.missingOIDCScope as string[]).join(' '));
      }

      // Add resource scopes
      if (details.missingResourceScopes) {
        for (const [indicator, scopes] of Object.entries(
          details.missingResourceScopes as Record<string, string[]>
        )) {
          grant.addResourceScope(indicator, scopes.join(' '));
        }
      }

      // Save grant
      const grantId = await grant.save();

      // Finish consent interaction
      const result: InteractionResults = {
        consent: {
          grantId,
        },
      };

      await provider.interactionFinished(req, res, result, {
        mergeWithLastSubmission: true,
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /interaction/:uid/abort
   * Handle consent form submission (deny)
   */
  router.post('/:uid/abort', async (req, res, next) => {
    try {
      const result: InteractionResults = {
        error: 'access_denied',
        error_description: 'End-user denied the authorization request',
      };

      await provider.interactionFinished(req, res, result, {
        mergeWithLastSubmission: false,
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

export default createInteractionRouter;
