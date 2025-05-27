# Use an official Node.js LTS runtime as a parent image (e.g., Node 20-slim)
FROM node:20-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# --- Node.js Application Setup for @bdmarvin/typingmind-mcp ---
# Copy package.json and package-lock.json first to leverage Docker cache.
COPY package.json ./
COPY package-lock.json* ./
# If you use pnpm or yarn, adjust accordingly:
# COPY pnpm-lock.yaml ./
# COPY yarn.lock ./

# Install dependencies for @bdmarvin/typingmind-mcp
# Using `npm ci` is recommended for production builds if you have a package-lock.json
RUN npm ci --omit=dev
# Or if you prefer/need `npm install`:
# RUN npm install --omit=dev
# Or if using pnpm (ensure pnpm is installed first, e.g., RUN npm install -g pnpm):
# RUN pnpm install --prod --frozen-lockfile

# Copy the rest of your application source code for @bdmarvin/typingmind-mcp
COPY . .

# If your @bdmarvin/typingmind-mcp application needs a build step (e.g., TypeScript to JavaScript)
# Ensure it's run here. For example:
# RUN npm run build 

# ENTRYPOINT for the Node.js MCP Controller
# This will use the npx bundled with Node.js to fetch and run your 
# bdmarvin1-mcp-server-ga4-node package from npm when a GA4 tool is called by the controller.
ENTRYPOINT ["npx", "@bdmarvin/typingmind-mcp"]
# Any arguments for @bdmarvin/typingmind-mcp itself are usually passed
# via Cloud Run's "Args" setting for the container, or (preferably) via environment variables
# configured in the Cloud Run service definition.
