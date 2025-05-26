# MCP OAuth Controller (formerly MCP Connector)

**@bdmarvin/typingmind-mcp** is an enhanced server that runs and manages multiple Model Context Protocol (MCP) servers and now includes robust Google OAuth 2.0 integration. It acts as a central OAuth controller, allowing downstream MCP servers to securely access Google services (like Google Search Console) on behalf of a user. This project is a fork and modification of the original `@typingmind/mcp` connector.

It's designed for integration with clients like [TypingMind](https://www.typingmind.com/mcp) and enables secure, authenticated access to Google APIs for your custom AI models and tools.

---

## Key Features

*   Manages multiple downstream MCP servers (e.g., started via STDIO).
*   Acts as a central **Google OAuth 2.0 Controller**:
    *   Handles the complete Google OAuth 2.0 Authorization Code flow.
    *   Securely stores Google refresh tokens using **Google Secret Manager**.
    *   Issues its own **User-Context MCP Token (JWT)** to represent an authenticated Google session.
    *   Validates this User-Context MCP Token for requests requiring Google context.
*   Dynamically provides fresh **Google Access Tokens** to downstream MCP servers when they need to call Google APIs.
*   Existing MCP Connector functionalities (server management, tool calls) remain, now augmented with Google OAuth capabilities.
*   Deployable via NPX, Docker, or directly on a server/Cloud Run.

---

## Setup and Configuration

### 1. Prerequisites

*   **Node.js:** Version 14 or later.
*   **Google Cloud Project:**
    *   Enable the **Secret Manager API**.
    *   Enable APIs for the Google services you intend to use (e.g., "Google Search Console API").
    *   Create **OAuth 2.0 Client ID credentials** (for "Web application"):
        *   Note your `Client ID` and `Client Secret`.
        *   Add **Authorized JavaScript origins** (e.g., `http://localhost:3000` for local dev, your Cloud Run URL `https://your-service.a.run.app`).
        *   Add **Authorized redirect URIs**:
            *   For local: `http://localhost:3000/oauth/google/callback` (adjust port if needed).
            *   For Cloud Run: `https://your-service.a.run.app/oauth/google/callback`.
    *   In **Secret Manager**, create a secret to store the Google refresh token (e.g., `typingmind-mcp-google-refresh-token`).
*   **IAM Permissions:**
    *   **For Local Development (using your user ADC - `gcloud auth application-default login`):** Your user account needs:
        *   `Secret Manager Secret Accessor` role (to read the refresh token).
        *   `Secret Manager Secret Version Adder` role (to store the refresh token).
        *   Grant these preferably on the specific secret created above.
    *   **For Cloud Run Deployment:** The **service account** used by your Cloud Run service needs the same roles (`Secret Manager Secret Accessor` and `Secret Manager Secret Version Adder`) on the secret.

### 2. Environment Variables

Create a `.env` file in the project root for local development, or set these in your Cloud Run environment:

```env
# Main Server Authentication
MCP_AUTH_TOKEN=your_strong_main_server_access_token

# Google OAuth Client Credentials
GOOGLE_CLIENT_ID=your_google_client_id_from_gcp_console
GOOGLE_CLIENT_SECRET=your_google_client_secret_from_gcp_console

# Google OAuth Redirect URI (MUST match one configured in GCP OAuth Client)
# For local development (ensure port matches if you set PORT env var):
GOOGLE_REDIRECT_URI=http://localhost:3000/oauth/google/callback
# For Cloud Run (replace with your actual service URL):
# GOOGLE_REDIRECT_URI=https://your-mcp-controller-url.a.run.app/oauth/google/callback

# Google Cloud Project & Secret Manager
GOOGLE_CLOUD_PROJECT=your_gcp_project_id_where_secret_lives
# Full path to the secret for loading the latest version
GOOGLE_REFRESH_TOKEN_SECRET_NAME_FOR_LOAD=projects/your_gcp_project_id/secrets/your_refresh_token_secret_id/versions/latest
# Full parent path to the secret for storing new versions
GOOGLE_REFRESH_TOKEN_SECRET_PARENT_FOR_STORE=projects/your_gcp_project_id/secrets/your_refresh_token_secret_id

# User-Context MCP Token (JWT) Configuration
MCP_USER_CONTEXT_JWT_SECRET=your_very_strong_random_secret_string_for_jwt_signing
MCP_USER_CONTEXT_JWT_EXPIRES_IN=1h # Optional, defaults to 1 hour (e.g., 1h, 7d, 30m)

# Optional Server Port (defaults to auto-discovery, e.g., 50880)
# PORT=3000
```

**Note on `your_refresh_token_secret_id`:** This is the ID you gave the secret in Secret Manager (e.g., `typingmind-mcp-google-refresh-token`).

### 3. Installation (if running from source)

```bash
git clone https://github.com/Bdmarvin1/typingmind-mcp.git
cd typingmind-mcp
git checkout building-oauth # Or your main working branch
pnpm install # or npm install
# Ensure you have dotenv installed for local .env loading (pnpm add dotenv)
# and require('dotenv').config() at the top of bin/index.js
```

---

## How to Run

### Running Locally (for Development/Testing)

1.  Ensure your `.env` file is configured.
2.  Make sure `require('dotenv').config();` is the first line in `bin/index.js`.
3.  Start the server:
    ```bash
    # Pass the main auth token as an argument if not in .env as MCP_AUTH_TOKEN
    pnpm start YOUR_MAIN_SERVER_AUTH_TOKEN
    # Or, if MCP_AUTH_TOKEN is in your .env and bin/index.js is set up to read it:
    # pnpm start
    ```
    The server will log the port it's running on.

### Using NPX (for published package)

Once published to npm under `@bdmarvin/typingmind-mcp`:

```bash
# Ensure all required environment variables listed above are set in your shell
# or in a .env file if you've modified bin/index.js to use dotenv.
npx @bdmarvin/typingmind-mcp YOUR_MAIN_SERVER_AUTH_TOKEN
```
Or, if `MCP_AUTH_TOKEN` is in the environment:
```bash
npx @bdmarvin/typingmind-mcp
```

### HTTPS Support

To enable HTTPS, set the `CERTFILE` and `KEYFILE` environment variables with paths to your SSL certificate and private key files.

---

## Google OAuth Flow

1.  **Initiate OAuth:**
    Open your browser and navigate to `YOUR_SERVER_BASE_URL/oauth/google/initiate`.
    *   Example (local): `http://localhost:3000/oauth/google/initiate`
    *   Example (Cloud Run): `https://your-mcp-controller-url.a.run.app/oauth/google/initiate`

2.  **Google Sign-in & Consent:**
    You will be redirected to Google. Sign in with the Google account that has access to the services you want this controller to manage (e.g., Google Search Console). Grant the requested permissions.

3.  **Callback & Token Generation:**
    Google will redirect back to your server's `/oauth/google/callback` URI.
    Your server will:
    *   Exchange the Google authorization code for Google access and refresh tokens.
    *   Securely store the Google refresh token in Google Secret Manager.
    *   Generate a **`user_context_mcp_token` (JWT)**.
    *   Return a JSON response containing this `user_context_mcp_token`.

    **Example JSON Response from `/oauth/google/callback`:**
    ```json
    {
      "message": "Google OAuth successful. ... User-Context MCP Token issued.",
      "user_context_mcp_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0...",
      "google_access_token_exists": true,
      "oauth_client_has_refresh_token": true
    }
    ```

4.  **Using the `user_context_mcp_token`:**
    *   The client application (e.g., TypingMind, or a tool like Postman/curl for testing) needs to store this `user_context_mcp_token`.
    *   For subsequent requests to this MCP OAuth Controller that require Google-authenticated actions (specifically to the `/clients/:id/call_tools` endpoint), the client **must** send this token in the `X-User-Context-MCP-Token` header.
        Example Header: `X-User-Context-MCP-Token: eyJhbGciOiJIUzI1NiIsI...`

---

## Interaction with Downstream MCP Servers

When this OAuth Controller calls a tool on a downstream MCP server (managed via STDIO, like the `@bdmarvin/mcp-server-gsc`):

1.  The incoming request to `/clients/:id/call_tools` must be authenticated with both the main server `authToken` (in `Authorization: Bearer`) AND the `user_context_mcp_token` (in `X-User-Context-MCP-Token`).
2.  The OAuth Controller validates both tokens.
3.  It uses its stored Google refresh token (associated with the user context from the JWT) to obtain a fresh Google Access Token.
4.  This Google Access Token, along with Google User ID and Email, are injected into the `arguments` object passed to the downstream MCP server's tool:
    *   `arguments.__google_access_token__`
    *   `arguments.__google_user_id__`
    *   `arguments.__google_user_email__`
5.  The downstream MCP server (e.g., `@bdmarvin/mcp-server-gsc`) must be designed to extract these from the arguments and use the `__google_access_token__` to make its API calls to Google services.

---

## Deploying to Google Cloud Run

1.  **Dockerfile:** A `Dockerfile` is included in the repository.
2.  **Build & Push Image:**
    Use Google Cloud Build to build the container image and push it to Google Artifact Registry (or Container Registry). Example `cloudbuild.yaml` might be needed.
    ```bash
    gcloud builds submit --tag gcr.io/YOUR_GCP_PROJECT_ID/mcp-oauth-controller:latest .
    ```
3.  **Deploy Service to Cloud Run:**
    ```bash
    gcloud run deploy mcp-oauth-controller-service \
      --image gcr.io/YOUR_GCP_PROJECT_ID/mcp-oauth-controller:latest \
      --platform managed \
      --region YOUR_REGION \
      --allow-unauthenticated \ # Or configure IAM for authenticated invocation
      --service-account YOUR_CLOUD_RUN_SERVICE_ACCOUNT_EMAIL \
      --port CONTAINER_PORT # e.g., 8080, which the Dockerfile EXPOSEs
      # Set all required environment variables (see "Environment Variables" section)
      # For sensitive variables (GOOGLE_CLIENT_SECRET, MCP_AUTH_TOKEN, MCP_USER_CONTEXT_JWT_SECRET),
      # create them as secrets in Secret Manager and link them in Cloud Run:
      # --set-secrets=GOOGLE_CLIENT_SECRET=your-gcp-secret-name:latest,MCP_AUTH_TOKEN=your-mcp-auth-token-secret:latest,...
    ```
    Ensure the `GOOGLE_REDIRECT_URI` environment variable for the Cloud Run service points to its own public HTTPS URL + `/oauth/google/callback`.
4.  **Service Account Permissions:** The Cloud Run service account needs `Secret Manager Secret Accessor` and `Secret Manager Secret Version Adder` roles for the Google refresh token secret.

---

## API Endpoints

All API endpoints (unless specified otherwise) require authentication via the main Bearer token (`Authorization: Bearer <MCP_AUTH_TOKEN>`).

| Endpoint                       | Method | Auth Required | User Context Token Required? | Description                                      |
|---------------------------------|--------|---------------|------------------------------|--------------------------------------------------|
| `/oauth/google/initiate`       | GET    | No            | No                           | Starts Google OAuth flow.                        |
| `/oauth/google/callback`       | GET    | No            | No                           | Handles Google OAuth callback, issues User-Context MCP Token. |
| `/ping`                        | GET    | Main Token    | No                           | Health check.                                    |
| `/test-user-context`           | GET    | Main Token    | Yes (`X-User-Context-MCP-Token`) | Tests User-Context MCP Token validation.         |
| `/start`                       | POST   | Main Token    | No                           | Start downstream MCP clients.                    |
| `/restart/:id`                 | POST   | Main Token    | No                           | Restart a specific client.                       |
| `/clients`                     | GET    | Main Token    | No                           | List running MCP clients.                        |
| `/clients/:id`                 | GET    | Main Token    | No                           | Get info for a specific client.                  |
| `/clients/:id/tools`           | GET    | Main Token    | No                           | List tools for a client.                         |
| `/clients/:id/call_tools`      | POST   | Main Token    | Yes (`X-User-Context-MCP-Token`) | Call a tool; injects Google tokens for downstream. |
| `/clients/:id`                 | DELETE | Main Token    | No                           | Stop and delete a client.                        |

---

## License

MIT
