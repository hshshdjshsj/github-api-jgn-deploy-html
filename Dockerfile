FROM node:24.21.0-bookworm-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev --ignore-scripts=false --no-audit --no-fund

COPY api/health.js ./health.js
COPY api/ptdin.js ./ptdin.js
COPY api/keamanan.js ./keamanan.js
COPY api/support.js ./support.mjs
COPY ["health server reco.js", "./health server reco.js"]
COPY cloudflare-server.js ./cloudflare-server.js

RUN node -e "const c=require('node:crypto'); if(process.version!=='v24.21.0'||typeof c.encapsulate!=='function'||typeof c.decapsulate!=='function') process.exit(91); const a=c.generateKeyPairSync('ml-kem-1024'); const b=c.generateKeyPairSync('ml-dsa-87'); if(a.publicKey.asymmetricKeyType!=='ml-kem-1024'||b.publicKey.asymmetricKeyType!=='ml-dsa-87') process.exit(92);" \
    && node -e "const a=require('argon2'); if(!a||typeof a.hash!=='function'||typeof a.verify!=='function') process.exit(93);" \
    && node --check health.js \
    && node --check ptdin.js \
    && node --check keamanan.js \
    && node --check support.mjs \
    && node --check "health server reco.js" \
    && node --check cloudflare-server.js

EXPOSE 8080
CMD ["node", "cloudflare-server.js", "main"]
