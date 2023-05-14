const test = require("tap").test;
const fastifyServer = require("./");

test("create server", (t) => {
  fastifyServer({
    shouldPerformJwtCheck: false,
  });
  t.end();
});

test("create server pino-pretty", (t) => {
  fastifyServer({
    shouldPerformJwtCheck: false,
    logger: {
      transport: {
        target: "pino-pretty",
      },
    },
  });
  t.end();
});
