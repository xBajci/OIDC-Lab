import 'dotenv/config';
import { getDb } from './db.js';
import { migrate } from './migrate.js';
import * as userRepo from './repos/users.js';
import * as oidcRepo from './repos/oidc-documents.js';
import * as credRepo from './repos/client-credentials.js';

const db = getDb();
const ISSUER = process.env.ISSUER || `http://localhost:${process.env.PORT || 3000}`;

// Support --clean flag
if (process.argv.includes('--clean')) {
  console.log('Cleaning database...');
  db.exec('DROP TABLE IF EXISTS users');
  db.exec('DROP TABLE IF EXISTS oidc_documents');
  db.exec('DROP TABLE IF EXISTS client_credentials');
  db.exec('DROP TABLE IF EXISTS flow_configs');
  console.log('All tables dropped');
}

// Run migrations (creates tables if they don't exist)
migrate(db);

// Create admin user (idempotent)
const existingUser = userRepo.findUserByUsername(db, 'admin');

if (existingUser) {
  console.log('Admin user already exists, skipping...');
} else {
  await userRepo.createUser(db, {
    username: 'admin',
    password: 'password',
    name: 'Admin User',
    email: 'admin@example.com',
    roles: ['admin'],
    emailVerified: true,
  });
  console.log('Created admin user:');
  console.log('  Username: admin');
  console.log('  Password: password');
}

// Upsert test client via repo
console.log('\nUpserting test client...');
const clientPayload = {
  client_id: 'test-client',
  client_secret: 'test-secret',
  client_name: 'Test Client',
  redirect_uris: [`${ISSUER}/flow/callback`],
  post_logout_redirect_uris: [`${ISSUER}/flow`],
  grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
  response_types: ['code'],
  scope: 'openid profile email offline_access',
  token_endpoint_auth_method: 'client_secret_basic',
  application_type: 'web',
};

oidcRepo.upsertDocument(db, {
  key: 'test-client',
  model: 'Client',
  payload: clientPayload,
});

credRepo.upsertCredentials(db, 'test-client', 'test-secret');

console.log('Upserted test client:');
console.log('  Client ID: test-client');
console.log('  Client Secret: test-secret');
console.log(`  Redirect URI: ${ISSUER}/flow/callback`);
console.log('  Grant Types: authorization_code, refresh_token, device_code');

console.log('\nSeed complete!');
console.log('\nYou can now:');
console.log('1. Start the app: bun run dev');
console.log(`2. Go to ${ISSUER}/flow`);
console.log('3. Enter client_id: test-client, client_secret: test-secret');
console.log('4. Start a flow and login with admin/password');
