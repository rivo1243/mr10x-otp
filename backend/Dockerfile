FROM node:20-alpine
WORKDIR /app
COPY backend/package.json .
RUN npm install --omit=dev
COPY backend/src ./src
# cache-bust: 2026-11-22-v3
COPY frontend ../frontend
EXPOSE 4000
CMD ["node", "src/server.js"]
