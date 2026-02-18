const PORT = process.env.PORT || 3000;
export const ISSUER = (process.env.ISSUER || `http://localhost:${PORT}`).replace(/\/$/, '');
