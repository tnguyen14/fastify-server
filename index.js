const fastify = require("fastify");
const fastifyJwt = require("@fastify/jwt");
const fastifySensible = require("@fastify/sensible");
const fastifyCors = require("@fastify/cors");
const isCallable = require("is-callable");
const qs = require("qs");
const jwksClient = require("jwks-rsa");

function createServer(options) {
  if (!options) {
    throw new Error("options cannot be empty");
  }
  const fastifyOptions = {
    logger: options.logger || {
      transport: {
        target: "pino-pretty",
      },
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

    const client = jwksClient({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${options.auth0Domain}/.well-known/jwks.json`,
    });
    server.register(fastifyJwt, {
      secret: async (request, token) => {
        // token
        /*
{
  header: {
    alg: 'RS256',
    typ: 'JWT',
    kid: 'REJEMEI4MzNBNDVFMTFBRDRGMTFFMkU5RERCRjhEQkJFMDk2NzRCNA'
  },
  payload: {
    iss: 'https://tridnguyen.auth0.com/',
    sub: 'google-oauth2|102956012089794272878',
    aud: [
      'https://lists.cloud.tridnguyen.com',
      'https://tridnguyen.auth0.com/userinfo'
    ],
    iat: 1681053925,
    exp: 1681140325,
    azp: 'z3IK464A6PogdpKe0LY0vTaKr6izei2a',
    scope: 'openid profile email offline_access'
  },
  signature: 'vqDsvNiflmMS-....6N24Zw-OkA',
  input: 'eyJhbGciOiJS...2Nlc3MifQ'
}
        */

        const {
          header: { alg, kid },
        } = token;
        // If algorithm is not using RS256, the encryption key is client secret
        if (alg.startsWith("HS")) {
          throw new Error("Please pass along Auth0 client secret");
        }
        if (alg !== "RS256") {
          throw new Error("Expecting RS256");
        }
        const key = await client.getSigningKey(kid);
        return key.getPublicKey();
      },
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
