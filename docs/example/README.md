# Example

1. Set a base domain in `.env`

1. Set up required ACME settings under the `certificatesresolvers.letsencrypt`
   CLI options in the `traefik` container

1. Add the environment variables required for the ACME provider in `.env.traefik`

1. Start Pocket ID

   ```sh
   docker compose up -d traefik pocket-id
   ```

   Then navigate to `/setup`, set up a user account, and create a new client.

   Enter those values in `.env.oidc-cookie-forward-auth`

1. Start the rest of the containers

   ```sh
   docker compose up --wait -d
   ```

   and then visit the protected service, e.g. <https://whoami.example.com>
