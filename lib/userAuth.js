const jwt = require('jsonwebtoken');
const MCP_USER_CONTEXT_JWT_SECRET = process.env.MCP_USER_CONTEXT_JWT_SECRET;

/**
 * Express middleware to validate the User-Context MCP Token.
 * This token is expected in the 'X-User-Context-MCP-Token' header.
 *
 * If valid, it attaches the decoded token payload to `req.googleUserContext`.
 */
function validateUserContextMcpToken(req, res, next) {
  if (!MCP_USER_CONTEXT_JWT_SECRET) {
    console.error('CRITICAL: MCP_USER_CONTEXT_JWT_SECRET is not set. Cannot validate User-Context MCP Tokens.');
    return res.status(500).json({ error: 'Server configuration error: User authentication mechanism is not properly configured.' });
  }

  const tokenHeader = req.headers['x-user-context-mcp-token'];

  if (!tokenHeader) {
    return res.status(401).json({ error: 'Unauthorized: User-Context MCP Token is required in X-User-Context-MCP-Token header.', code: 'TOKEN_MISSING' });
  }

  const parts = tokenHeader.split(' ');
  let actualToken = tokenHeader;
  if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
    actualToken = parts[1];
  } else if (parts.length > 1 && parts[0].toLowerCase() !== 'bearer') {
     return res.status(401).json({ error: 'Unauthorized: Invalid User-Context MCP Token format in X-User-Context-MCP-Token header.', code: 'TOKEN_FORMAT_INVALID' });
  } else if (parts.length > 2 && parts[0].toLowerCase() === 'bearer') {
     return res.status(401).json({ error: 'Unauthorized: Invalid User-Context MCP Token format in X-User-Context-MCP-Token header.', code: 'TOKEN_FORMAT_INVALID_MULTI' });
  }


  try {
    const decoded = jwt.verify(actualToken, MCP_USER_CONTEXT_JWT_SECRET);
    req.googleUserContext = decoded; 
    console.log('User-Context MCP Token validated successfully for sub:', decoded.sub, 'email:', decoded.email);
    next();
  } catch (err) {
    console.warn('User-Context MCP Token validation failed:', err.message, '(Token received:', actualToken.substring(0, 20) + '...)');
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Unauthorized: User-Context MCP Token has expired.', code: 'TOKEN_EXPIRED' });
    }
    if (err.name === 'JsonWebTokenError') { 
      return res.status(401).json({ error: 'Unauthorized: Invalid User-Context MCP Token.', code: 'TOKEN_INVALID_SIGNATURE_OR_MALFORMED' });
    }
    return res.status(401).json({ error: 'Unauthorized: Could not validate User-Context MCP Token.', code: 'TOKEN_VALIDATION_UNKNOWN_ERROR' });
  }
}

module.exports = {
  validateUserContextMcpToken,
};
