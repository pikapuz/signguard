FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY guard.js server.js ./
COPY public ./public
EXPOSE 8000
CMD ["node", "server.js"]
