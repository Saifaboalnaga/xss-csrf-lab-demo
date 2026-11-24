FROM node:20-alpine
ENV NODE_ENV=production BIND_HOST=0.0.0.0
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --chown=node:node server.js ./
COPY --chown=node:node public ./public
USER node
EXPOSE 3000 4000
CMD ["node", "server.js"]
