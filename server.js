import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/") {
    fs.createReadStream(path.resolve("src", "index.html")).pipe(res);
    return;
  }
});

const connectedSockets = new Set();
const CONN_UPGRADE_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

server.on("upgrade", (req, socket) => {
  const secWebSocketKey = req.headers["sec-websocket-key"];
  if (!secWebSocketKey) {
    socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
    socket.destroy();
    return;
  }

  const secWebSocketAccept = crypto
    .createHash("sha1")
    .update(secWebSocketKey + CONN_UPGRADE_MAGIC_STRING)
    .digest("base64");

  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: WebSocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${secWebSocketAccept}\r\n\r\n`
  );

  connectedSockets.add(socket);

  socket.on("end", () => {
    connectedSockets.delete(socket);
  });

  socket.on("error", () => {
    connectedSockets.delete(socket);
  });

  socket.on("readable", () => {
    processDataFrame(socket);
  });
});

const PORT = 3000;
server.listen(PORT, () => console.log(`server running on port ${PORT}`));

["uncaughtException", "unhandledRejection"].forEach((event) =>
  process.on(event, (err) => {
    console.error(`an unhandled error(${event}):`, err.stack || err);
  })
);

const BM_FIN = 0b1000_0000;
const BM_OPCODE = 0b0000_1111;
const BM_MASKED = 0b1000_0000;
const BM_EXP_LEN = 0b0111_1111;

const OP_TEXT = 0x1;

const LEN_7_BITS = 125;
const LEN_16_BITS = 126;
const LEN_64_BITS = 127;

function processDataFrame(socket) {
  const [finAndOpcode] = socket.read(1);
  const opcode = finAndOpcode & BM_OPCODE;

  const [maskAndPayloadLen] = socket.read(1);
  const isMasked = maskAndPayloadLen & BM_MASKED;

  if (!isMasked) {
    socket.destroy();
    return;
  }

  const expectedPayloadLen = maskAndPayloadLen & BM_EXP_LEN;
  let payloadLen = 0;

  if (expectedPayloadLen <= LEN_7_BITS) {
    payloadLen = expectedPayloadLen;
  } else if (expectedPayloadLen === LEN_16_BITS) {
    const buffer = socket.read(2);
    payloadLen = buffer.readUInt16BE();
  } else if (expectedPayloadLen === LEN_64_BITS) {
    const buffer = socket.read(8);
    payloadLen = buffer.readBigUint64BE();
  }

  const mask = socket.read(4);
  const maskedPayload = socket.read(payloadLen);
  let payload = maskedPayload.map((e, i) => e ^ mask[i % 4]);

  if (connectedSockets.size <= 1) return;

  const resFrame = createResponseFrame(payload);

  for (const s of connectedSockets) {
    if (s !== socket) {
      s.write(resFrame);
    }
  }
}

function createResponseFrame(payload) {
  let payloadLenBuffer;

  if (payload.length <= 125) {
    payloadLenBuffer = Buffer.alloc(1);
    payloadLenBuffer.writeUInt8(payload.length);
  } else if (payload.length <= 2 ** 16 - 1) {
    payloadLenBuffer = Buffer.alloc(2);
    payloadLenBuffer.writeUint16BE(payload.length);
  } else {
    payloadLenBuffer = Buffer.alloc(8);
    payloadLenBuffer.writeBigUInt64BE(payload.length);
  }

  const frame = Buffer.alloc(1 + payloadLenBuffer.length + payload.length);
  frame[0] = 0x81; 
  payloadLenBuffer.copy(frame, 1);
  payload.copy(frame, 1 + payloadLenBuffer.length);

  return frame;
}
