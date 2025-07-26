# OIDC Cookie Forward-Auth

This is a simple forward-auth middleware for Traefik that handles cookie-based
auth on behalf of a user authenticated via OpenID Connect.

Apps such as [tinyauth](https://github.com/steveiliop56/tinyauth) or
[oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) can protect
unauthenticated apps or apps that support auth via a plain header, but do not
provide support for stateful authentication.

This forward-auth middleware keeps track of cookies as part of the forward-auth
session, and provides them to the Traefik forward-auth handler, to be used in
the origin request.

The forward-auth endpoint / server is never exposed. Everything is handled via
the forward-auth middleware.

## Setup

### Prerequisites

- A reverse proxy with forward-auth support (only [Traefik][traefik] is
  currently supported)
- An OIDC provider, such as [Pocket ID][pocket-id]. Any provider conforming to
  the OIDC specification should work.

[traefik]: https://doc.traefik.io/traefik/getting-started/install-traefik/
[pocket-id]: https://github.com/pocket-id/pocket-id

### Configuration reference

#### Environment variables

| Name                   | Description                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------ |
| CLIENT_ID              | OAuth2 Client ID                                                                     |
| CLIENT_SECRET          | OAuth2 Client Secret                                                                 |
| OIDC_ISSUER_CONFIG_URL | Fully qualified OIDC issuer URL, e.g. `https://auth.example.com/`                    |
| SQLITE_PATH            | Database file, e.g. `/var/lib/oidc/db/sessions.db`, defaults to in-memory if not set |
| DOMAIN_BASE            | Base domain, used to shorten the config filenames                                    |
| UNSAFE_COOKIE_INSECURE | Can be set to `true` or `1` to enable using insecure session cookies                 |

#### Configuration files

You must create a new config file in `/var/lib/oidc/config/` for each host you
want to support.

For example, if you have `https://whoami.example.com`, set your `DOMAIN_BASE` to
`.example.com`, and create a config file in at `/var/lib/oidc/config/whoami.ts`.

### Step-by-step

> [!TIP]
> There's a complete example in the [./docs/example/ directory](./docs/example/)

1. Make sure you have [Traefik set up with SSL](https://doc.traefik.io/traefik/https/overview/)
   correctly

1. Create a new OIDC client in your provider. The redirect URL is
   `https://whoami.example.com/oauth2/callback` – the same host as your regular
   service. The forward-auth proxy itself is not exposed.

   If you need to protect multiple hosts, you can set a wildcard redirect URL,
   list all the hosts, or create a client per host (as well as a forward-auth
   container and middleware per host).

1. Add the forward-auth container:

   ```yaml
   services:
     # ...
     oidc-cookie-forward-auth:
       image: ghcr.io/nihalgonsalves/oidc-cookie-forward-auth:latest
       # depends_on:
       #   pocket-id:
       #     condition: service_healthy
       restart: unless-stopped
       env_file:
         # this file should contain:
         # CLIENT_ID=...
         # CLIENT_SECRET=...
         - .env.oidc-cookie-forward-auth
       environment:
         # you can omit this and the DB volume if you'd like sessions not to
         # be persisted across container restarts
         SQLITE_DB: /var/lib/oidc/db/sessions.db
         OIDC_ISSUER_CONFIG_URL: "https://auth.example.com/.well-known/openid-configuration"
         DOMAIN_BASE: ".example.com"
       volumes:
         - oidc-db:/var/lib/oidc/db
         # or other local path to store the config
         - ./config/:/var/lib/oidc/config
       expose:
         - 3000
       labels:
         traefik.enable: true
         traefik.http.middlewares.oidc-cookie-forward-auth.forwardauth.address: http://oidc-cookie-forward-auth:3000/oauth2/traefik
         traefik.http.middlewares.oidc-cookie-forward-auth.forwardauth.authResponseHeaders: cookie

   # ...

   volumes:
     oidc-db:
   ```

1. Create a config file:

   ```ts
   export const config = {
     // this is any function that returns a fetch Response containing
     // the Set-Cookie headers
     getUpstreamCookies: () =>
       fetch(new URL("http://whoami:80/auth/signin"), {
         method: "POST",
         body: new URLSearchParams({
           // you can also add env variables to the cookie auth file
           // and reference them using process.env.NAME
           username: "admin",
           password: "password",
         }),
       }),
     // this is a validation request to make sure the session is still valid.
     // use any URL that is only accessible when logged in.
     // this enables the user to use logout functionality inside the origin
     // app and seamlessly invalidate the OIDC session too.
     validateUpstreamSession: async (headers: Bun.HeadersInit) => {
       try {
         const response = await fetch(new URL("http://whoami:80/me"), {
           headers,
           redirect: "manual",
         });

         return response.ok;
       } catch {
         return false;
       }
     },
   };
   ```

1. That's it. Start the container, and visit your service, for example
   <https://whoami.example.com/>. You should be redirected to the OIDC provider.

   Once logged in there, `getUpstreamCookies` will be called to log in to
   the origin service, creating a session in the forward-auth service.

   Every subsequent request will be re-validated using `validateUpstreamSession`,
   and then the valid cookies will be sent to the reverse proxy to be provided
   to the origin request.
