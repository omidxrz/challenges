# Use the official Node.js image.
FROM node:latest

# Create and change to the app directory.
WORKDIR /usr/src/app

# Copy application dependency manifests to the container image.
COPY package*.json ./

# Install dependencies.
RUN npm install

# Copy local code to the container image.
COPY index.js .
COPY views views
COPY public public

# Expose port 3000.
EXPOSE 3000

# Run the web service on container startup.
CMD [ "node", "index.js" ]
