const fastify = require("fastify");
const fastifySecretProvider = require("fastify-authz-jwks");
const fastifyJwt = require("fastify-jwt");
const fastifySensible = require("fastify-sensible");
const fastifyCors = require("fastify-cors");
const isCallable = require("is-callable");

function createServer(options) {
  if (!options) {
    throw new Error("options cannot be empty");
  }
  if (!options.auth0Domain) {
    throw new Error("auth0Domain is required");
  }
  if (!options.auth0ClientId) {
    throw new Error("auth0ClientId is required");
  }
  const fastifyOptions = {
    logger: options.logger || false,
    ignoreTrailingSlash: options.ignoreTrailingSlash || true,
  };

  const nojwtCheckRoutes = options.nojwtCheckRoutes || ["/healthcheck"];
  const allowedOrigins = options.allowedOrigins || [];

  const server = fastify(fastifyOptions);

  server.register(fastifySensible);

  server.register(fastifyJwt, {
    secret: fastifySecretProvider({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${options.auth0Domain}/.well-known/jwks.json`,
    }),
    audience: options.auth0ClientId,
    issuer: `https://${options.auth0Domain}`,
    algorithms: ["RS256"],
    decode: { complete: true },
  });

  server.register(fastifyCors, {
    origin: allowedOrigins,
  });

  server.addHook("preValidation", async (request, reply) => {
    if (options.shouldPerformJwtCheck != undefined) {
      if (isCallable(options.shouldPerformJwtCheck)) {
        if (!options.shouldPerformJwtCheck(request)) {
          return;
        }
      }
      if (!options.shouldPerformJwtCheck) {
        return;
      }
    }
    try {
      if (
        nojwtCheckRoutes.every((route) => {
          return !request.req.url.match(new RegExp(route));
        })
      ) {
        await request.jwtVerify();
      }
    } catch (err) {
      reply.send(err);
    }
  });
}

module.exports = createServer;
