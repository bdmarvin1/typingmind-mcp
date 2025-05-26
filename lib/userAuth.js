const jwt = require('jsonwebtoken');
const MCP_USER_CONTEXT_JWT_SECRET = process.env.MCP_USER_CONTEXT_JWT_SECRET;

/**
 * Express middleware to validate the User-Context MCP Token.
 * TEMP MODIFICATION: This will bypass strict validation for now if token is missing,
 * but will attempt to decode if present. Sets placeholder googleUserContext if no token.
 *
 * Token is expected in the 'X-User-Context-MCP-Token' header.
 * If valid/present, it attaches decoded token payload to `req.googleUserContext`.
 */
function validateUserContextMcpToken(req, res, next) {
  console.warn('TEMP BYPASS: User-Context MCP Token validation is currently in a permissive mode.');

  const tokenHeader = req.headers['x-user-context-mcp-token'];
  let actualToken = null;

  if (tokenHeader) {
    const parts = tokenHeader.split(' ');
    if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
      actualToken = parts[1];
    } else if (parts.length === 1) {
      actualToken = parts[0];
    } else {
        console.warn('User-Context MCP Token header format appears invalid, ignoring.');
        // Not returning error, just won't have a token to decode
    }
  }

  if (actualToken && MCP_USER_CONTEXT_JWT_SECRET) {
    try {
      const decoded = jwt.verify(actualToken, MCP_USER_CONTEXT_JWT_SECRET);
      req.googleUserContext = decoded;
      console.log('User-Context MCP Token (if provided) was VALIDATED successfully for sub:', decoded.sub, 'email:', decoded.email);
    } catch (err) {
      console.warn('User-Context MCP Token (if provided) FAILED validation:', err.message, '- proceeding without user context from token.');
      // Set a default/empty context or indicate failure to downstream if critical
      // For now, let's set a flag or make it clear it's not truly validated
      req.googleUserContext = { sub: null, email: null, error: 'Token validation failed: ' + err.name };
    }
  } else if (actualToken && !MCP_USER_CONTEXT_JWT_SECRET) {
      console.error('CRITICAL: MCP_USER_CONTEXT_JWT_SECRET is not set. Cannot validate provided User-Context MCP Token.');
      req.googleUserContext = { sub: null, email: null, error: 'JWT secret missing on server, token not validated.' };
  } else {
    console.log('No User-Context MCP Token provided in header. Proceeding without it.');
    // Set a placeholder so req.googleUserContext exists, as downstream code might expect it.
    // The downstream code MUST then check if sub/email are null.
    req.googleUserContext = { sub: null, email: null, note: 'No token provided by client' };
  }

  next(); // Always call next() to allow the request to proceed
}

module.exports = {
  validateUserContextMcpToken,
};
