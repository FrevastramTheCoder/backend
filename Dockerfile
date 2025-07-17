# Use official Node.js 18 image with Alpine (lightweight)
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install dependencies for node-gyp and PostGIS client libraries
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    postgresql-client

# Copy package files first for better caching
COPY package*.json ./

# Install production dependencies only
RUN npm install --production

# Copy the rest of the application
COPY . .

# Expose the application port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD node healthcheck.js || exit 1

# Command to run the application
CMD ["node", "server.js"]