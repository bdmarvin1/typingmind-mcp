const express = require('express');
const stringify = require('json-stable-stringify');
const cors = require('cors');
const fs = require('fs');
const https = require('https');
const { findAvailablePort } = require('./port-finder');
const { authMiddleware } = require('./auth');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const {
  StdioClientTransport,
  getDefaultEnvironment,
} = require('@modelcontextprotocol/sdk/client/stdio.js');

// Added for Google OAuth
const { google } = require('googleapis');
const crypto = require('crypto');
const jwt = require('jsonwebtoken'); 

// Added for Google Secret Manager
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const { validateUserContextMcpToken } = require('./userAuth'); 

const secretManagerClient = new SecretManagerServiceClient();

// Google OAuth Configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;
const GOOGLE_CLOUD_PROJECT = process.env.GOOGLE_CLOUD_PROJECT; 

// Secret Manager Configuration
const GOOGLE_REFRESH_TOKEN_SECRET_NAME_FOR_LOAD = process.env.GOOGLE_REFRESH_TOKEN_SECRET_NAME_FOR_LOAD;
const GOOGLE_REFRESH_TOKEN_SECRET_PARENT_FOR_STORE = process.env.GOOGLE_REFRESH_TOKEN_SECRET_PARENT_FOR_STORE;

// User-Context MCP Token JWT Configuration
const MCP_USER_CONTEXT_JWT_SECRET = process.env.MCP_USER_CONTEXT_JWT_SECRET;
const MCP_USER_CONTEXT_JWT_EXPIRES_IN = process.env.MCP_USER_CONTEXT_JWT_EXPIRES_IN || '1h';

// List of client IDs that require Google context injection
const GOOGLE_AWARE_CLIENT_IDS = ['mcp-server-gsc', 'ga4-node-service']; // Add other GSC or Google-dependent client IDs here

let oauth2Client; 
const oauthStates = new Set();
const clients = new Map();

async function startClient(clientId, config) {
  const { command, args = [], env = {} } = config; 
  if (!command) {
    throw new Error('Command is required');
  }
  const transport = new StdioClientTransport({
    command,
    args,
    env: 
      Object.values(env).length > 0
        ? { ...getDefaultEnvironment(), ...env }
        : getDefaultEnvironment(), 
  });
  const client = new Client({
    name: `mcp-http-bridge-${clientId}`,
    version: '1.0.0',
  });
  await client.connect(transport);
  clients.set(clientId, {
    id: clientId,
    client,
    transport, 
    command,
    args,
    initialEnv: env, 
    config, 
    createdAt: new Date(),
  });
  return { id: clientId, message: 'MCP client started successfully' };
}

async function start(authToken) {
  const app = express();

  if (!MCP_USER_CONTEXT_JWT_SECRET) {
    console.warn('CRITICAL WARNING: MCP_USER_CONTEXT_JWT_SECRET environment variable is not set. Server will not be able to issue User-Context MCP Tokens for Google authenticated sessions. OAuth flow will be incomplete.');
  }

  if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_REDIRECT_URI) {
    oauth2Client = new google.auth.OAuth2(
      GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET,
      GOOGLE_REDIRECT_URI
    );

    if (GOOGLE_REFRESH_TOKEN_SECRET_NAME_FOR_LOAD) {
      try {
        console.log(`Attempting to load refresh token from Secret Manager: ${GOOGLE_REFRESH_TOKEN_SECRET_NAME_FOR_LOAD}`);
        const [version] = await secretManagerClient.accessSecretVersion({
          name: GOOGLE_REFRESH_TOKEN_SECRET_NAME_FOR_LOAD,
        });
        const refreshToken = version.payload.data.toString('utf8');
        if (refreshToken) {
          oauth2Client.setCredentials({ refresh_token: refreshToken });
          console.log('Successfully loaded and set refresh token from Secret Manager on startup.');
        } else {
          console.warn('Loaded refresh token from Secret Manager is empty. User may need to authenticate via OAuth flow.');
        }
      } catch (error) {
        if (error.code === 5) { 
          console.warn(`Refresh token secret not found (${GOOGLE_REFRESH_TOKEN_SECRET_NAME_FOR_LOAD}). User will need to authenticate via OAuth flow to create/populate it.`);
        } else {
          console.error('Failed to load refresh token from Secret Manager on startup:', error.message);
        }
      }
    } else {
        console.warn('GOOGLE_REFRESH_TOKEN_SECRET_NAME_FOR_LOAD not set. Cannot load refresh token on startup.');
    }
  } else {
    console.warn('Google OAuth environment variables (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI) are not fully set. OAuth routes will not function correctly.');
  }

  const port = process.env.PORT || (await findAvailablePort());
  if (!port) {
    throw new Error('No available ports found. Please specify a port by using the PORT environment variable.');
  }

  app.use(cors());
  app.use(express.json());

  app.get('/oauth/google/initiate', (req, res) => {
    if (!oauth2Client) {
      return res.status(500).json({ error: 'OAuth2 client is not configured. Missing credentials, redirect URI, or refresh token load failed.' });
    }
    const state = crypto.randomBytes(16).toString('hex');
    oauthStates.add(state);
    const scopes = [
      'https://www.googleapis.com/auth/webmasters.readonly',
      'https://www.googleapis.com/auth/analytics.readonly',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
      'openid' 
    ];
    const authorizationUrl = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: scopes,
      prompt: 'consent',
      state: state
    });
    res.redirect(authorizationUrl);
  });

  app.get('/oauth/google/callback', async (req, res) => {
    const { code, state } = req.query;
    if (!oauth2Client) {
      return res.status(500).json({ error: 'OAuth2 client is not configured.' });
    }
    if (!state || !oauthStates.has(state)) {
      oauthStates.delete(state);
      return res.status(400).json({ error: 'Invalid state parameter or CSRF attempt.' });
    }
    oauthStates.delete(state);
    if (!code) {
      return res.status(400).json({ error: 'Authorization code missing.' });
    }

    try {
      const { tokens } = await oauth2Client.getToken(code);
      console.log('Google OAuth Tokens obtained from code exchange:', tokens);
      if(tokens.access_token) oauth2Client.setCredentials(tokens);

      let message = 'Google OAuth successful. ';
      let refreshMessage = 'Token processing: ';

      if (tokens.refresh_token) {
        refreshMessage += 'New refresh token received. ';
        if (GOOGLE_REFRESH_TOKEN_SECRET_PARENT_FOR_STORE && GOOGLE_CLOUD_PROJECT) {
          try {
            console.log(`Attempting to store new refresh token in Secret Manager: ${GOOGLE_REFRESH_TOKEN_SECRET_PARENT_FOR_STORE}`);
            await secretManagerClient.addSecretVersion({
              parent: GOOGLE_REFRESH_TOKEN_SECRET_PARENT_FOR_STORE,
              payload: { data: Buffer.from(tokens.refresh_token, 'utf8') },
            });
            refreshMessage += 'Successfully stored in Secret Manager.';
            console.log(refreshMessage);
          } catch (secretError) {
            console.error('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
            console.error('Failed to store new refresh token in Secret Manager:');
            console.error('Error Code:', secretError.code); 
            console.error('Error Details:', secretError.details); 
            console.error('Full Secret Error Object:', JSON.stringify(secretError, null, 2)); 
            console.error('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
            refreshMessage += 'Failed to store in Secret Manager. Check server logs for details.';
          }
        } else {
          refreshMessage += 'Secret Manager store path (GOOGLE_REFRESH_TOKEN_SECRET_PARENT_FOR_STORE or GOOGLE_CLOUD_PROJECT) not configured; token not stored persistently.';
          console.warn(refreshMessage);
        }
      } else if (tokens.access_token && !oauth2Client.credentials.refresh_token) {
        refreshMessage += 'No new refresh token. ';
         if (GOOGLE_REFRESH_TOKEN_SECRET_NAME_FOR_LOAD) {
            try {
                console.log('Attempting to load existing refresh token for oauth2Client from callback...');
                const [version] = await secretManagerClient.accessSecretVersion({
                    name: GOOGLE_REFRESH_TOKEN_SECRET_NAME_FOR_LOAD,
                });
                const existingRefreshToken = version.payload.data.toString('utf8');
                if (existingRefreshToken) {
                    oauth2Client.setCredentials({ refresh_token: existingRefreshToken });
                    refreshMessage += 'Successfully loaded existing refresh token on OAuth client.';
                    console.log(refreshMessage);
                } else {
                    refreshMessage += 'Existing refresh token from Secret Manager was empty.';
                    console.warn(refreshMessage);
                }
            } catch (loadError) {
                console.error('Failed to load existing refresh token from Secret Manager for callback:', loadError);
                refreshMessage += 'Failed to load existing refresh token.';
            }
        } else {
            refreshMessage += 'No path configured to load existing refresh token (GOOGLE_REFRESH_TOKEN_SECRET_NAME_FOR_LOAD).';
            console.warn(refreshMessage);
        }
      } else {
        refreshMessage += 'No new refresh token. OAuth client might already have one from startup or an error occurred if access_token is also missing.';
      }
      
      message += refreshMessage;

      let userContextMcpToken = null;
      if (!MCP_USER_CONTEXT_JWT_SECRET) {
        console.error('CRITICAL: MCP_USER_CONTEXT_JWT_SECRET is not set. Cannot issue User-Context MCP Token.');
        message += ' However, User-Context MCP Token could not be issued due to missing server configuration (JWT Secret).';
      } else if (!oauth2Client.credentials || !oauth2Client.credentials.access_token) {
        message += ' Cannot issue User-Context MCP Token: Google access token not available on oauth2Client for fetching user info.';
        console.warn('Cannot issue User-Context MCP Token: Google access token missing from oauth2Client when trying to fetch user info.');
      } else {
        try {
          let googleUserInfo = { id: null, email: null }; 
          try {
            console.log('Attempting to fetch Google User Info for JWT...');
            const userInfoClient = google.oauth2('v2').userinfo;
            const userInfoResponse = await userInfoClient.get({ auth: oauth2Client });
            googleUserInfo = userInfoResponse.data; 
            console.log('Fetched Google User Info for JWT:', { id: googleUserInfo.id, email: googleUserInfo.email });
          } catch (userInfoError) {
            console.warn('Failed to fetch Google user info directly for JWT. Error:', userInfoError.message);
            if (tokens.id_token) { 
                try {
                    const decodedIdToken = jwt.decode(tokens.id_token); 
                    if (decodedIdToken) {
                        googleUserInfo.id = decodedIdToken.sub;
                        googleUserInfo.email = decodedIdToken.email;
                        console.log('Populated user info from id_token for JWT:', {id: googleUserInfo.id, email: googleUserInfo.email});
                    }
                } catch (e) { console.warn("Could not decode id_token for user info fallback for JWT:", e.message);}
            }
             if (!googleUserInfo.id && !googleUserInfo.email) {
                console.warn("Could not obtain Google User ID or email for JWT subject.");
            }
          }

          const issuedAt = Math.floor(Date.now() / 1000);
          const payload = {
            sub: googleUserInfo.id, 
            email: googleUserInfo.email, 
            iss: 'TypingMindMCPController', 
            iat: issuedAt,
          };

          userContextMcpToken = jwt.sign(
            payload,
            MCP_USER_CONTEXT_JWT_SECRET,
            { expiresIn: MCP_USER_CONTEXT_JWT_EXPIRES_IN }
          );
          message += ' User-Context MCP Token issued.';
          console.log('User-Context MCP Token issued successfully.');

        } catch (jwtError) {
          console.error('Error signing User-Context MCP Token:', jwtError);
          message += ' Failed to issue User-Context MCP Token due to internal error.';
          userContextMcpToken = null; 
        }
      }

      res.status(200).json({
        message: message,
        user_context_mcp_token: userContextMcpToken,
        google_access_token_exists: !!tokens.access_token,
        oauth_client_has_refresh_token: !!oauth2Client.credentials.refresh_token
      });

    } catch (error) {
      console.error('Error in OAuth callback token processing:', error.response?.data || error.message);
      res.status(500).json({ error: 'Failed during OAuth callback token processing.' });
    }
  });

  const auth = authMiddleware(authToken);
  app.get('/ping', auth, (req, res) => { res.status(200).json({ status: 'ok' }); });

  app.get('/test-user-context', auth, validateUserContextMcpToken, (req, res) => {
    res.status(200).json({
      message: 'Successfully accessed test route with valid User-Context MCP Token!',
      googleUserContext: req.googleUserContext,
    });
  });

  app.post('/start', auth, async (req, res) => {
    try {
      const { mcpServers } = req.body;
      const results = { success: [], errors: [] };
      const startPromises = Object.entries(mcpServers).map(
        async ([serverId, config]) => {
          try {
            if (clients.has(serverId)) {
              const hasConfigChanged = stringify(clients.get(serverId).config) !== stringify(config);
              if (!hasConfigChanged) return;
              console.log('Restarting client with new config:', serverId);
              if (clients.get(serverId).client && typeof clients.get(serverId).client.close === 'function') {
                await clients.get(serverId).client.close(); 
              }
            }
            const result = await startClient(serverId, config);
            results.success.push(result);
          } catch (error) {
            console.error(`Failed to initialize client ${serverId}:`, error);
            results.errors.push({ id: serverId, error: `Failed to initialize: ${error.message}` });
          }
        }
      );
      await Promise.all(startPromises);
      if (results.errors.length === 0) {
        return res.status(201).json({ message: 'All MCP clients started successfully', clients: results.success });
      } else {
        return res.status(400).json({ message: 'Some MCP clients failed to start', success: results.success, errors: results.errors });
      }
    } catch (error) {
      console.error('Error starting clients:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/restart/:id', auth, async (req, res) => {
    const { id } = req.params;
    const clientEntry = clients.get(id);
    if (!clientEntry) return res.status(404).json({ error: 'Client not found' });
    try {
      const config = clientEntry.config || { command: clientEntry.command, args: clientEntry.args, env: clientEntry.initialEnv }; 
      if (clientEntry.client && typeof clientEntry.client.close === 'function') {
         await clientEntry.client.close(); 
      }
      clients.delete(id);
      const result = await startClient(id, config); 
      return res.status(200).json({ message: `Client ${id} restarted successfully`, client: result });
    } catch (error) {
      console.error(`Error restarting client ${id}:`, error);
      return res.status(500).json({ error: 'Failed to restart client', details: error.message });
    }
  });

  app.get('/clients', auth, async (req, res) => {
    try {
      const clientDetailsPromises = Array.from(clients.values()).map(
        async (clientEntry) => {
          const { id, command, args, createdAt } = clientEntry;
          try {
            const result = await clientEntry.client.listTools();
            const tools = result.tools || [];
            const toolNames = tools.map((tool) => tool.name);
            return { id, command, args, createdAt, tools: toolNames };
          } catch (error) {
            console.error(`Error getting tools for client ${id}:`, error);
            return { id, command, args, createdAt, tools: [], toolError: error.message };
          }
        }
      );
      const clientsList = await Promise.all(clientDetailsPromises);
      res.status(200).json(clientsList);
    } catch (error) {
      console.error('Error fetching clients list:', error);
      res.status(500).json({ error: 'Failed to retrieve clients list', details: error.message });
    }
  });

  app.get('/clients/:id', auth, (req, res) => {
    const clientId = req.params.id;
    const clientEntry = clients.get(clientId);
    if (!clientEntry) return res.status(404).json({ error: 'Client not found' });
    const { id, command, args, createdAt } = clientEntry;
    res.status(200).json({ id, command, args, createdAt });
  });

  app.get('/clients/:id/tools', auth, async (req, res) => {
    const { id } = req.params;
    const clientEntry = clients.get(id);
    if (!clientEntry) return res.status(404).json({ error: 'Client not found' });
    try {
      const result = await clientEntry.client.listTools();
      res.status(200).json(result.tools);
    } catch (error) {
      console.error(`Error getting tools for client ${id}:`, error);
      res.status(500).json({ error: 'Failed to get tools', details: error.message });
    }
  });

  app.post('/clients/:id/call_tools', auth, validateUserContextMcpToken, async (req, res) => {
    const { id: downstreamClientId } = req.params; 
    const { name: toolName, arguments: originalToolArgs = {} } = req.body; 

    if (!toolName) {
      return res.status(400).json({ error: 'Tool name is required' });
    }

    const clientEntry = clients.get(downstreamClientId);
    if (!clientEntry) {
      return res.status(404).json({ error: `Client ${downstreamClientId} not found` });
    }

    let finalToolArgs = originalToolArgs;

    if (GOOGLE_AWARE_CLIENT_IDS.includes(downstreamClientId)) {
        if (!oauth2Client || !oauth2Client.credentials || !oauth2Client.credentials.refresh_token) {
            console.error(`call_tools: oauth2Client for Google user ${req.googleUserContext.email} (sub: ${req.googleUserContext.sub}) is not properly configured with a refresh token for Google-aware client '${downstreamClientId}'.`);
            return res.status(500).json({ 
                error: 'Server not configured to obtain Google Access Token for this client. OAuth flow may be incomplete or refresh token missing.',
                code: 'GOOGLE_AUTH_UNINITIALIZED_FOR_CLIENT'
            });
        }
        
        console.log(`call_tools: Client '${downstreamClientId}' is Google-aware. Authorized by main token. User context token validated for sub=${req.googleUserContext.sub}, email=${req.googleUserContext.email}`);

        try {
            console.log('call_tools: Attempting to get fresh Google Access Token...');
            const { token: freshGoogleAccessToken } = await oauth2Client.getAccessToken();

            if (!freshGoogleAccessToken) {
                console.error('call_tools: Failed to obtain fresh Google Access Token despite having a refresh token.');
                return res.status(500).json({ error: 'Failed to obtain necessary Google Access Token to call downstream tool.', code: 'GOOGLE_ACCESS_TOKEN_ERROR' });
            }
            console.log('call_tools: Successfully obtained fresh Google Access Token.');

            finalToolArgs = {
                ...originalToolArgs,
                __google_access_token__: freshGoogleAccessToken,
                __google_user_id__: req.googleUserContext.sub, 
                __google_user_email__: req.googleUserContext.email
            };
        } catch (error) {
            console.error(`call_tools: Error during Google Access Token retrieval for client ${downstreamClientId}:`, error);
            if (error.response && error.response.data) { 
                console.error('Underlying Google API Error Data:', error.response.data);
                return res.status(error.response.status || 500).json({ 
                    error: 'Failed to process request due to an issue with Google services when obtaining access token.',
                    code: 'GOOGLE_API_ERROR',
                    details: error.response.data.error || error.message
                });
            }
            return res.status(500).json({
                error: 'Failed to call tool due to an internal error related to Google authentication.',
                code: 'CALL_TOOL_GOOGLE_AUTH_ERROR',
                details: error.message,
            });
        }
    } else {
        console.log(`call_tools: Client '${downstreamClientId}' is NOT Google-aware. Passing original arguments only.`);
    }

    try {
        console.log(`call_tools: Calling tool '${toolName}' on client '${downstreamClientId}'.`);
        const result = await clientEntry.client.callTool({
            name: toolName,
            arguments: finalToolArgs, 
        });
        res.status(200).json(result);
    } catch (toolError) {
        console.error(`call_tools: Error while executing tool '${toolName}' on client '${downstreamClientId}':`, toolError);
        return res.status(500).json({
            error: `Failed to execute tool '${toolName}' on client '${downstreamClientId}'.`,
            code: 'MCP_TOOL_EXECUTION_ERROR',
            details: toolError.message || String(toolError)
        });
    }
  });

  app.delete('/clients/:id', auth, async (req, res) => {
    const { id } = req.params;
    const clientEntry = clients.get(id);
    if (!clientEntry) return res.status(404).json({ error: 'Client not found' });
    try {
      if (clientEntry.client && typeof clientEntry.client.close === 'function') {
        await clientEntry.client.close(); 
      }
      clients.delete(id);
      res.status(200).json({ message: 'Client deleted successfully' });
    } catch (error) {
      console.error(`Error deleting client ${id}:`, error);
      res.status(500).json({ error: 'Failed to delete client', details: error.message });
    }
  });

  app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  });

  return new Promise((resolve, reject) => {
    const host = process.env.HOSTNAME || '0.0.0.0';
    const certFile = process.env.CERTFILE;
    const keyFile = process.env.KEYFILE;
    let server;
    if (certFile && keyFile) {
      try {
        const httpsOptions = { cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) };
        server = https.createServer(httpsOptions, app);
        server.listen(port, host, () => { resolve({ port, host, protocol: 'https' }); });
      } catch (error) {
        console.error('Error setting up HTTPS server:', error);
        reject(error);
      }
    } else {
      server = app.listen(port, host, () => { resolve({ port, host, protocol: 'http' }); });
    }
    const serverCloseHandler = () => {
      console.log('\nShutting down MCP HTTP server...');
      server.close(() => { console.log('MCP HTTP server closed.'); });
    };
    process.on('SIGINT', serverCloseHandler);
    process.on('SIGTERM', serverCloseHandler);
  });
}

async function handleShutdown() {
  console.log('Received shutdown signal. Closing MCP clients...');
  for (const [id, clientEntry] of clients.entries()) {
    try {
      if (clientEntry.client && typeof clientEntry.client.close === 'function') {
         await clientEntry.client.close();
      }
      console.log(`Closed client ${id}`);
    } catch (error) {
      console.error(`Error closing client ${id}:`, error);
    }
  }
  process.exit(0);
}
process.on('SIGINT', handleShutdown);
process.on('SIGTERM', handleShutdown);

module.exports = { start };
