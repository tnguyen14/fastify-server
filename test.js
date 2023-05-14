const test = require("tap").test;
const fastifyServer = require("./");

test("create server", (t) => {
  fastifyServer({
    shouldPerformJwtCheck: false,
  });
  t.end();
});
