const fastify = require("fastify");
const fastifySecretProvider = require("fastify-authz-jwks");
const fastifyJwt = require("@fastify/jwt");
const fastifySensible = require("@fastify/sensible");
const fastifyCors = require("@fastify/cors");
const isCallable = require("is-callable");
const qs = require("qs");

function createServer(options) {
  if (!options) {
    throw new Error("options cannot be empty");
  }
  const fastifyOptions = {
    logger: options.logger || {
      prettyPrint: process.env.NODE_ENV != "production",
    },
    ignoreTrailingSlash: options.ignoreTrailingSlash || true,
    querystringParser: (str) => qs.parse(str),
  };

  const nojwtCheckRoutes = options.nojwtCheckRoutes || ["/healthcheck"];
  const allowedOrigins = options.allowedOrigins || [];

  const server = fastify(fastifyOptions);

  server.register(fastifySensible);
  server.register(fastifyCors, {
    origin: allowedOrigins,
  });

  if (options.shouldPerformJwtCheck != false) {
    if (!options.auth0Domain) {
      throw new Error("auth0Domain is required");
    }
    if (!options.auth0ClientId) {
      throw new Error("auth0ClientId is required");
    }
    server.register(fastifyJwt, {
      secret: fastifySecretProvider({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${options.auth0Domain}/.well-known/jwks.json`,
      }),
      audience: options.audience || options.auth0ClientId,
      issuer: `https://${options.auth0Domain}`,
      algorithms: ["RS256"],
      decode: { complete: true },
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
            return !request.url.match(new RegExp(route));
          })
        ) {
          await request.jwtVerify();
        }
      } catch (err) {
        console.error(err);
        reply.badRequest(err.message || "JWT verification failed");
      }
    });
  }
  return server;
}

module.exports = createServer;
