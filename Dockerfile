FROM node:20-slim
WORKDIR /app
COPY package.json .
COPY engine/ ./engine/
COPY bin/ ./bin/
RUN chmod +x bin/verifyd.cjs
EXPOSE 8080
CMD [" node\, in/server.cjs\]
