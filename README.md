# pontoon

## Overview
Blockchain wallet-as-a-service application, with the following features that allow users to:

- Securely connect to the service
- Securely generate a signature key
- Securely generate signatures on messages
- Securely be forgotten by the services

## Design

B2B platform architecture.

### Admin

Component responsible for managing clients (tenants).
Upon successful registration client will be given a unique API key and secret which should be used then to secure wallet communication.

#### Admin API Endpoints

- **POST /admin/client**
  - Create a new client (tenant) for the wallet service.
  - Request body:
  ```json
  { 
    "name": "<string>"
  }
  ```
  - Response: `201 Created`:
  ```json
  { 
    "id": "<uuid>",
    "name": "<string>",
    "credentials": {
        "api_key": "<uuid>",
        "secret": "<string>"
    }
  }
  ```
  NOTE: secret will be shown only once upon client creation.

- **GET /admin/client?id={client_id}**
  - Get details for a specific client.
  - Response: `200 OK`:
  ```json
  { 
    "name": "<string>",  
    "api_key": "<uuid>"
  }
  ```

Since admin component shall have a dashboard for clients:
  - add password and email fields to client creation
  - add authentication via JWT token in the `Authorization: Bearer <token>` header

### Wallet

Components responsible for managing user wallets.

### Wallet authentication

All wallet endpoints require authentication headers:
  - `x-api-key`: API key for the client/tenant
  - `x-timestamp`: Current UNIX timestamp
  - `x-signature`: HMAC SHA256 signature of the request calculated as follows:
    - compose a message string to be signed: *{unix timestamp}{http method}{request path}{request query}{request body}*
    - sign message with secret provided at registration using HMAC SHA-256
    - base64 encode the signature

#### Wallet API Endpoints

- **POST /wallet/register**
  - Register a new wallet user.
  - Headers: 
    - `x-api-key`
    - `x-timestamp`
    - `x-signature`
  - Response: `201 Created`:
    ```json
    {
      "user_id": "<uuid>",
      "pub_key": "<PEM-formatted public key>"
    }
    ```

- **POST /wallet/{user_id}/sign**
  - Sign a message with the user's private key.
  - Path parameter: `user_id` (UUID)
  - Request body: raw string message
  - Response: `200 OK`:
    ```json
    {
      "message": "<original message>",
      "signature": "<hex signature>"
    }
    ```

- **DELETE /wallet/{user_id}/revoke**
  - Revoke (delete) a wallet user and all associated keys.
  - Path parameter: `user_id` (UUID)
  - Response: `204 No Content` on success


## Deployment

### Local

In order to run locally, you will need to set up a PostgreSQL database and configure the application to connect to it. You can use Docker Compose to easily spin up the required services.

1. Start the database:
   ```bash
   docker-compose up -d
   ```

2. Run migrations:
  2.1 Install the required tools (if not present):
   ```bash
   cargo install sqlx-cli
   ```
   2.2 Set up the database URL:
   ```bash
   export DATABASE_URL=postgres://admin:admin@localhost:5432/pontoon
   ```
   2.3 Run the migrations:
   ```bash
   sqlx migrate run
   ```
3. Start admin component, from */admin* folder run:
   ```bash
   cargo make run-local
   ```
4. Start the wallet component, from */wallet* folder run:
   ```bash
   cargo make run-local
   ```

### Staging
  *TODO*

### Production
  *TODO*

## Testing

1.  Create a new client using the Admin API. Save the `api_key` and `secret`.
2.  Register a new wallet user using the Wallet API. Save the `user_id` and `pub_key`.
3.  Sign a message using the Wallet API. Check signature on a verification service, like https://emn178.github.io/online-tools/rsa/verify/ using `pub_key`.
4.  Revoke the wallet user using the Wallet API.