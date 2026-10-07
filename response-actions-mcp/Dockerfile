FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ src/
COPY test/ test/
RUN npm test

FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/dist dist/
EXPOSE 3001
ENV PORT=3001
CMD ["node", "dist/server.js"]
