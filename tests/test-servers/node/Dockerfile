FROM node:18-alpine
WORKDIR /app
RUN npm install node-forge
COPY server.js .
EXPOSE 8444
CMD ["node", "server.js"]
