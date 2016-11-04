# Kinetic library

Kinetic library create and handle requests to communicate with kinetic drives.
It is based on the kinetic protocol, available at
https://github.com/Kinetic/kinetic-protocol

## Implementation

### Architecture

The kinetic library consist of a principal class PDU that handles the
requests. It takes the buffer received from the kinetic drives or the client
and decode it. The request are in protobuf
(https://developers.google.com/protocol-buffers/) so they are small.
The library don't do the I/O with the kinetic drives. The I/O have to be
done by the user. The library encode and decode protobuf messages following
the kinetic protocol.

In this library we got requests that extend from PDU.
That design allow to create requests easily. A request will just be an instance
of PDU.

### Library specifications

Right now, the following operations are implemented:

- PDU,
- InitPDU (server),
- GetLogPDU (client),
- GetLogResponsePDU,
- FlushPDU (client),
- FlushResponsePDU (server),
- SetClusterVersionPDU (client),
- SetupResponsePDU (server),
- NoOpPDU (client),
- NoOpResponsePDU (server),
- PutPDU (client),
- PutResponsePDU (server),
- GetPDU (client),
- GetResponsePDU (server),
- DeletePDU (client),
- DeleteResponsePDU (server),
