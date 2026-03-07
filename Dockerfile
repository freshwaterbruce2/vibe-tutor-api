FROM node:22-slim

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.mjs ./

# Render uses PORT env variable
ENV PORT=10000
EXPOSE 10000

CMD ["node", "server.mjs"]
