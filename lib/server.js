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

// Google OAuth Configuration (loaded from environment variables)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

let oauth2Client; // To be initialized in start()
const oauthStates = new Set(); // Simple CSRF state store (see caveats in discussion)


// Store active MCP clients
const clients = new Map();

// Helper function to start a client with given configuration
async function startClient(clientId, config) {
  const { command, args = [], env = {} } = config;

  if (!command) {
    throw new Error('Command is required');
  }

  // Create transport for the MCP client
  const transport = new StdioClientTransport({
    command,
    args,
    env:
      Object.values(env).length > 0
        ? {
            // see https://github.com/modelcontextprotocol/typescript-sdk/issues/216
            ...getDefaultEnvironment(),
            ...env,
          }
        : undefined, // cannot be {}, it will cause error
  });

  // Create and initialize the client
  const client = new Client({
    name: `mcp-http-bridge-${clientId}`,
    version: '1.0.0',
  });

  // Connect the client to the transport
  await client.connect(transport);

  // Store the client with its ID
  clients.set(clientId, {
    id: clientId,
    client,
    transport,
    command,
    args,
    env,
    config, // Store original config for restart
    createdAt: new Date(),
  });

  return {
    id: clientId,
    message: 'MCP client started successfully',
  };
}

/**
 * Start the MCP server
 * @param {string} authToken Authentication token
 * @returns {Promise<{port: number}>} The port the server is running on
 */
async function start(authToken) {
  const app = express();

  // Initialize Google OAuth2 Client
  if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_REDIRECT_URI) {
    oauth2Client = new google.auth.OAuth2(
      GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET,
      GOOGLE_REDIRECT_URI
    );
  } else {
    console.warn('Google OAuth environment variables (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI) are not fully set. OAuth routes will not function correctly.');
  }

  // Find an available port
  const port = process.env.PORT || (await findAvailablePort());
  if (!port) {
    throw new Error(
      'No available ports found. Please specify a port by using the PORT environment variable.'
    );
  }

  // Configure middleware
  app.use(cors());
  app.use(express.json());


  // --- Google OAuth Routes (Public) ---
  app.get('/oauth/google/initiate', (req, res) => {
    if (!oauth2Client) {
      return res.status(500).json({ error: 'OAuth2 client is not configured. Missing credentials or redirect URI.' });
    }

    const state = crypto.randomBytes(16).toString('hex');
    oauthStates.add(state);

    const scopes = [
      'https://www.googleapis.com/auth/webmasters.readonly', // For Google Search Console
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
    ];

    const authorizationUrl = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: scopes,
      prompt: 'consent', // Ensures refresh token is sent, good for dev
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
      oauthStates.delete(state); // Clean up if state exists
      return res.status(400).json({ error: 'Invalid state parameter or CSRF attempt.' });
    }
    oauthStates.delete(state); // Valid state, remove after use

    if (!code) {
      return res.status(400).json({ error: 'Authorization code missing.' });
    }

    try {
      const { tokens } = await oauth2Client.getToken(code);
      // For Task 2.1, we just log tokens. Task 2.2 will store them. Task 2.3 issues MCP token.
      console.log('Google OAuth Tokens obtained:', tokens);

      res.status(200).json({
        message: 'Google OAuth successful. Tokens obtained (logged on server). Next steps: store tokens and issue MCP token.',
        google_access_token_exists: !!tokens.access_token,
        google_refresh_token_exists: !!tokens.refresh_token
      });

    } catch (error) {
      console.error('Error exchanging code for tokens:', error.response?.data || error.message);
      res.status(500).json({ error: 'Failed to exchange authorization code for tokens.' });
    }
  });

  // --- End Google OAuth Routes ---


  // Add authentication to all subsequent endpoints
  const auth = authMiddleware(authToken);

  // Health check endpoint
  app.get('/ping', auth, (req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  // Start MCP clients using Claude Desktop config format
  app.post('/start', auth, async (req, res) => {
    try {
      const { mcpServers } = req.body;

      const results = {
        success: [],
        errors: [],
      };

      // Process each server configuration
      const startPromises = Object.entries(mcpServers).map(
        async ([serverId, config]) => {
          try {
            // Check if this client already exists
            if (clients.has(serverId)) {
              const hasConfigChanged =
                stringify(clients.get(serverId).config) !== stringify(config);
              if (!hasConfigChanged) {
                return;
              }
              console.log('Restarting client with new config:', serverId);
              clients.get(serverId).client.close();
            }

            const result = await startClient(serverId, config);
            results.success.push(result);
          } catch (error) {
            console.error(`Failed to initialize client ${serverId}:`, error);
            results.errors.push({
              id: serverId,
              error: `Failed to initialize: ${error.message}`,
            });
          }
        }
      );

      // Wait for all clients to be processed
      await Promise.all(startPromises);

      // Return appropriate response
      if (results.errors.length === 0) {
        return res.status(201).json({
          message: 'All MCP clients started successfully',
          clients: results.success,
        });
      } else {
        return res.status(400).json({
          message: 'Some MCP clients failed to start',
          success: results.success,
          errors: results.errors,
        });
      }
    } catch (error) {
      console.error('Error starting clients:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Restart a specific client
  app.post('/restart/:id', auth, async (req, res) => {
    const { id } = req.params;
    const clientEntry = clients.get(id);

    if (!clientEntry) {
      return res.status(404).json({ error: 'Client not found' });
    }

    try {
      // Get the original configuration
      const config = clientEntry.config || {
        command: clientEntry.command,
        args: clientEntry.args,
        env: clientEntry.env,
      };

      // Close the existing client
      await clientEntry.client.close();
      clients.delete(id);

      // Start a new client with the same configuration
      const result = await startClient(id, config);

      return res.status(200).json({
        message: `Client ${id} restarted successfully`,
        client: result,
      });
    } catch (error) {
      console.error(`Error restarting client ${id}:`, error);
      return res.status(500).json({
        error: 'Failed to restart client',
        details: error.message,
      });
    }
  });

  app.get('/clients', auth, async (req, res) => {
    try {
      // Create an array of promises that will fetch tools for each client
      const clientDetailsPromises = Array.from(clients.values()).map(
        async (clientEntry) => {
          const { id, command, args, createdAt } = clientEntry;

          try {
            // Get tools for this client
            const result = await clientEntry.client.listTools();
            const tools = result.tools || [];

            // Extract just the tool names into an array
            const toolNames = tools.map((tool) => tool.name);

            return {
              id,
              command,
              args,
              createdAt,
              tools: toolNames,
            };
          } catch (error) {
            console.error(`Error getting tools for client ${id}:`, error);
            return {
              id,
              command,
              args,
              createdAt,
              tools: [],
              toolError: error.message,
            };
          }
        }
      );

      // Wait for all promises to resolve
      const clientsList = await Promise.all(clientDetailsPromises);

      res.status(200).json(clientsList);
    } catch (error) {
      console.error('Error fetching clients list:', error);
      res.status(500).json({
        error: 'Failed to retrieve clients list',
        details: error.message,
      });
    }
  });

  app.get('/clients/:id', auth, (req, res) => {
    const clientId = req.params.id;
    const clientEntry = clients.get(clientId);

    if (!clientEntry) {
      return res.status(404).json({ error: 'Client not found' });
    }

    const { id, command, args, createdAt } = clientEntry;

    res.status(200).json({ id, command, args, createdAt });
  });

  // Get tools for a specific client
  app.get('/clients/:id/tools', auth, async (req, res) => {
    const { id } = req.params;
    const clientEntry = clients.get(id);

    if (!clientEntry) {
      return res.status(404).json({ error: 'Client not found' });
    }

    try {
      const result = await clientEntry.client.listTools();
      res.status(200).json(result.tools);
    } catch (error) {
      console.error(`Error getting tools for client ${id}:`, error);
      res.status(500).json({
        error: 'Failed to get tools',
        details: error.message,
      });
    }
  });

  // Call a tool for a specific client
  app.post('/clients/:id/call_tools', auth, async (req, res) => {
    const { id } = req.params;
    const { name, arguments: toolArgs } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Tool name is required' });
    }

    const clientEntry = clients.get(id);
    if (!clientEntry) {
      return res.status(404).json({ error: 'Client not found' });
    }

    try {
      const result = await clientEntry.client.callTool({
        name,
        arguments: toolArgs || {},
      });

      res.status(200).json(result);
    } catch (error) {
      console.error(`Error calling tool for client ${id}:`, error);
      res.status(500).json({
        error: 'Failed to call tool',
        details: error.message,
      });
    }
  });

  // Clean up resources for a client
  app.delete('/clients/:id', auth, async (req, res) => {
    const { id } = req.params;
    const clientEntry = clients.get(id);

    if (!clientEntry) {
      return res.status(404).json({ error: 'Client not found' });
    }

    try {
      // Close the client properly
      await clientEntry.client.close();
      clients.delete(id);

      res.status(200).json({ message: 'Client deleted successfully' });
    } catch (error) {
      console.error(`Error deleting client ${id}:`, error);
      res.status(500).json({
        error: 'Failed to delete client',
        details: error.message,
      });
    }
  });

  // Global error handler
  app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
      error: 'Internal server error',
      details: err.message,
    });
  });

  // Start the server (HTTP or HTTPS)
  return new Promise((resolve, reject) => {
    const host = process.env.HOSTNAME || '0.0.0.0';

    // Check if certificate and key files are specified
    const certFile = process.env.CERTFILE;
    const keyFile = process.env.KEYFILE;

    let server;

    if (certFile && keyFile) {
      try {
        // Read certificate files
        const httpsOptions = {
          cert: fs.readFileSync(certFile),
          key: fs.readFileSync(keyFile),
        };

        // Create HTTPS server
        server = https.createServer(httpsOptions, app);
        server.listen(port, host, () => {
          resolve({ port, host, protocol: 'https' });
        });
      } catch (error) {
        console.error('Error setting up HTTPS server:', error);
        reject(error);
      }
    } else {
      // Create HTTP server (fallback)
      server = app.listen(port, host, () => {
        resolve({ port, host, protocol: 'http' });
      });
    }

    // Handle graceful shutdown for this server instance
    // Note: The global SIGINT handler below also closes clients.
    const serverCloseHandler = () => {
      console.log('\nShutting down MCP HTTP server...');
      server.close(() => {
        console.log('MCP HTTP server closed.');
        // process.exit(0); // The global SIGINT handler will manage process exit
      });
    };
    
    process.on('SIGINT', serverCloseHandler);
    process.on('SIGTERM', serverCloseHandler);

  });
}

// Graceful shutdown handling for clients (global)
// This was slightly modified to be an async function and to be clearer
async function handleShutdown() {
  console.log('Received shutdown signal. Closing MCP clients...');
  for (const [id, clientEntry] of clients.entries()) {
    try {
      await clientEntry.client.close();
      console.log(`Closed client ${id}`);
    } catch (error) {
      console.error(`Error closing client ${id}:`, error);
    }
  }
  process.exit(0); // Exit after attempting to close all clients
}

process.on('SIGINT', handleShutdown);
process.on('SIGTERM', handleShutdown);


module.exports = {
  start,
};
