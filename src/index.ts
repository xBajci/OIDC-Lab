import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import { engine } from 'express-handlebars';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDb } from './db.js';
import { migrate } from './migrate.js';
import { cleanupExpired } from './repos/oidc-documents.js';
import { createProvider } from './config/provider.js';
import { createInteractionRouter } from './routes/interaction.js';
import { createAdminRouter } from './routes/admin.js';
import { createFlowRouter } from './routes/flow.js';
import { ISSUER } from './config/env.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me';

async function main() {
  const db = getDb();
  migrate(db);
  console.log('SQLite database initialized');

  const app = express();

  // Session middleware (needed for flow starter PKCE/state/nonce)
  app.use(
    session({
      secret: SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: false,
        maxAge: 10 * 60 * 1000,
      },
    })
  );

  // Handlebars with merged helpers from both server and client
  app.engine(
    'hbs',
    engine({
      extname: '.hbs',
      defaultLayout: 'main',
      layoutsDir: path.join(__dirname, 'views/layouts'),
      partialsDir: path.join(__dirname, 'views/partials'),
      helpers: {
        json: (context: unknown) => JSON.stringify(context, null, 2),
        eq: (a: unknown, b: unknown) => a === b,
        includes: (arr: unknown[] | undefined, val: unknown) =>
          Array.isArray(arr) && arr.includes(val),
        or: (...args: unknown[]) => args.slice(0, -1).some(Boolean),
        substring: (str: unknown, start: number, end: number) =>
          typeof str === 'string' ? str.substring(start, end) : '',
        formatDate: (date: Date) => {
          if (!date) return '';
          return new Date(date).toLocaleString();
        },
        truncate: (str: string, len: number) => {
          if (!str) return '';
          if (str.length <= len) return str;
          return str.substring(0, len) + '...';
        },
      },
    })
  );
  app.set('view engine', 'hbs');
  app.set('views', path.join(__dirname, 'views'));

  // Single URL for everything
  app.locals.serverUrl = ISSUER;

  // Create OIDC provider
  console.log('Creating OIDC provider...');
  const provider = await createProvider();

  // Request logging
  app.use((req, res, next) => {
    const start = Date.now();
    const originalEnd = res.end.bind(res);
    res.end = function (...args: Parameters<typeof res.end>) {
      const duration = Date.now() - start;
      const wwwAuth = res.getHeader('www-authenticate');
      const logParts = [
        `[REQ] ${req.method} ${req.originalUrl} → ${res.statusCode} (${duration}ms)`,
      ];
      if (wwwAuth) {
        logParts.push(`  ⚠ WWW-Authenticate: ${wwwAuth}`);
      }
      console.log(logParts.join('\n'));
      return originalEnd(...args);
    } as typeof res.end;
    next();
  });

  // Body parsing for non-provider routes
  const parseBody = [express.urlencoded({ extended: false }), express.json()];

  // Mount routes
  const interactionRouter = createInteractionRouter(provider);
  app.use('/interaction', parseBody, interactionRouter);

  const adminRouter = createAdminRouter(provider);
  app.use('/admin', parseBody, adminRouter);

  const flowRouter = createFlowRouter();
  app.use('/flow', parseBody, flowRouter);

  // Home redirect
  app.get('/', (req, res) => {
    res.redirect('/admin');
  });

  // OIDC provider
  app.use(provider.callback());

  // Error handler
  app.use(
    (
      err: Error,
      req: express.Request,
      res: express.Response,
      next: express.NextFunction
    ) => {
      console.error('Error:', err);
      res.status(500).render('error', {
        title: 'Error',
        error: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
      });
    }
  );

  app.listen(PORT, () => {
    console.log(`OIDC Lab running at http://localhost:${PORT}`);
    console.log(`Admin dashboard: http://localhost:${PORT}/admin`);
    console.log(`Flow Starter: http://localhost:${PORT}/flow`);
    console.log(`Discovery: http://localhost:${PORT}/.well-known/openid-configuration`);

    setInterval(() => {
      cleanupExpired(getDb());
    }, 10 * 60 * 1000);
  });
}

main().catch((err) => {
  console.error('Failed to start:', err);
  process.exit(1);
});
