# kineticlib -- JavaScript Kinetic library

Node.js library for using the [Kinetic open storage
protocol](https://github.com/Kinetic/kinetic-protocol).
This library supports protocol 3.0.7

For the full documentation, visit
[here](https://kinetic.github.io/kinetic-js/)

## Requirements

This project's code is written in ES6. If you need to include it from older
JavaScript versions, use babel or an equivalent.

Install npm dependencies using `npm install`.

## Examples

Create a PDU for a PUT at key "mykey" and send it to localhost on port 1234:

```js
import net from 'net';
import kinetic from 'kineticlib';

const chunk = new Buffer("D4T4d4t4D4T4d4t4D4T4d4t4D4T4d4t4D4T4d4t4");
const options = {
    dbVersion: new Buffer('44'),        // The actual version of the value in
                                        // the database
    newVersion: new Buffer('45'),       // The updated version of the value in
                                        // the database
    force: false                        // Setting force to true ignores
                                        // potential version mismatches and
                                        // carries out the operation.
    clusterVersion                      // the cluster version
}

const pdu = new kinetic.PutPDU(
    1,                                   // sequence number
    "mykey",                             // key
    chunk.length,                        // chunkSize
    options,                             // options
);

const sock = net.connect(1234, 'localhost');
sock.on("end", () => {
    process.stdout.write("PDU sent through the network.\n");
});

sock.write(pdu.read());
sock.write(chunk);
```

Decode a PDU message from a buffer:

```js
const rawData = new Buffer('\x46\x00\x00\x00\x32\x00' ... );

const pdu = new kinetic.PDU(rawData);

const type = pdu.getMessageType();
process.stdout.write("Received " + kinetic.getOpName(type) + " PDU.\n");

if (type === kinetic.ops.GET)
    process.stdout.write("Peer is trying to GET key " + pdu.getKey() + ".\n");
```

Asynchronously decode a PDU from a stream (e.g. a socket):

Handle a decoding error:

```js
const badBuffer = new Buffer('\x46\x00\x00\x00\x32\x00');

try {
    const pdu = new kinetic.PDU(badBuffer);
} catch (e) {
    if (e.badLength)
        process.stdout.write("Message is either truncated or too long.\n");
    else if (e.hmacFail)
        process.stdout.write("Message is corrupted.\n");
    // ...
}
```

Receive a response from kinetic:

```js
const header = socket.sock.read(HEADER_SZ);
const protobufSize = header.readInt32BE(1);
const rawData = socket.sock.read(protobufSize);
const pdu = new kinetic.PDU(Buffer.concat([header, rawData]));
const statusCode = pdu.getStatusCode();
const connectionInfos = {};
let chunkSize = 0;
let chunk = Buffer.from(0);

switch (pdu.getMessageType()) {
//Initial pdu received from the kinetic drive with infos
case null:
    //These infos are needed for the nexts request
    connectionInfos.connectionID = pdu.getConnectionId();
    connectionInfos.clusterVersion = pdu.getClusterVersion();
    break;
case kinetic.ops.PUT_RESPONSE:
    if (statusCode !== kinetic.errors.SUCCESS) {
        return callback(pdu.getErrorMessage());
    }
    return callback(null, pdu);
    break;
case kinetic.ops.DELETE_RESPONSE:
    if (statusCode !== kinetic.errors.SUCCESS) {
        return callback(pdu.getErrorMessage());
    }
    return callback(null, pdu);
    break;
case kinetic.ops.GET_RESPONSE:
    if (statusCode !== kinetic.errors.SUCCESS) {
        return callback(pdu.getErrorMessage());
    }
    chunkSize = pdu.getChunkSize();
    chunk = socket.sock.read(chunkSize);
    return callback(null, pdu, chunk);
    break;
default:
    break;
```
