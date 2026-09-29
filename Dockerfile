FROM node:20-slim
WORKDIR /app
COPY package.json ./
COPY ab-relay.mjs ./
ENV BIND=0.0.0.0
EXPOSE 8080
CMD ["node", "ab-relay.mjs"]