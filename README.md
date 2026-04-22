## Simple fastify server

### Usage

```js
require("dotenv").config();

const server = require("@tridnguyen/fastify-server")({
  auth0Domain: "tridnguyen.auth0.com",
  audience: "https://example-api.tridnguyen.com",
  allowedOrigins: [
    "https://subdomain.tridnguyen.com",
    "https://tridnguyen.com",
  ],
  shouldPerformJwtCheck: false,
});

server.setErrorHandler((err, request, reply) => {
  console.error(err);
  reply.send(err);
});

async function start() {
  try {
    await server.listen(process.env.PORT || 3000, "0.0.0.0");
    console.log("Server started");
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

start();
```

#### Options

- `options.logger`: boolean. Defaults to `false`.
- `options.ignoreTrailingSlash`: boolean. Defaults to `true`.
- `options.auth0Domain`: string. Required unless `shouldPerformJwtCheck` is `false`.
- `options.audience`: string. Required unless `shouldPerformJwtCheck` is `false`. Should be the Auth0 API identifier (e.g. `https://your-api.example.com`).
- `options.allowedOrigins`: array. Defaults to `[]`.
- `options.shouldPerformJwtCheck`: boolean or a function. If a function, it should return `true` if jwt validation is needed, `false` otherwise. Default to validate JWT.
