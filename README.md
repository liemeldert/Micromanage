# Micromanage
 MicroMDM-based mdm service (basically a web-ui for micromdm)

## Setup
 * Requires a working MicroMDM server, follow their docs on getting that working.
 * Deploy with Docker:
```yaml
version: '3.8'

services:
  micromdm:
    image: sphen/micromdm
    container_name: micromdm
    restart: always
    environment:
      - SERVER_URL=https://mdm.example.com
      - API_KEY=change me please
      - COMMAND_WEBHOOK_URL=https://dash.micromanage.app/tenant/webhook/secret
    volumes:
      - ./micromdm:/config
      - ./mdmrepo:/repo
    ports:
      - "8080:8080"
   
  mongo:
    image: mongo
    restart: always
    environment:
      MONGO_INITDB_ROOT_USERNAME: root
      MONGO_INITDB_ROOT_PASSWORD: secure password
    ports:
      - 27017:27017 
    volumes:
      - ./mdmdata/db:/data/db

  micromanage_web:
    image: ghcr.io/liemeldert/micromanage:latest
    restart: always
    environment:
        AUTH_SECRET: secure random characters
        AUTH_GOOGLE_ID: "blabla.apps.googleusercontent.com"
        AUTH_GOOGLE_SECRET: "1234567890"

        AUTH_GITHUB_ID: "1234567890"
        AUTH_GITHUB_SECRET: "1234567890"

        AUTH_URL: "https://dash.micromanage.app"
        MONGODB_URI: "mongodb://root:secure password@mongo:27017"
        DB_SECRET: secure random characters
    ports:
      - 3000:3000

networks:
  default:
    driver: overlay
```
