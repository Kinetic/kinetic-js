import assert from 'assert';
import crypto from 'crypto';
import net from 'net';

import kinetic from '../../index';

const HOST = '127.0.0.1';
const PORT = 8123;
const chunk = Buffer.from('CHUNK');
const key = Buffer.from('key');
const startKey = Buffer.from('key');
const endKey = Buffer.from('key5');
const maxRet = 100;

let sequence = 0;
let connectionID = 0;
let clusterVersion = 0;
const newVersion = Buffer.from('1');


const requestsArr = [
    ['put', 'PUT_RESPONSE'],
    ['get', 'GET_RESPONSE', {}, { key, }],
    ['put', 'PUT_RESPONSE', { newVersion, }],
    ['getVersion', 'GETVERSION_RESPONSE'],
    ['put', 'PUT_RESPONSE', { key: Buffer.from('key1') }],
    ['put', 'PUT_RESPONSE', { key: Buffer.from('key2') }],
    ['put', 'PUT_RESPONSE', { key: Buffer.from('key3') }],
    ['put', 'PUT_RESPONSE', { key: Buffer.from('key4') }],
    ['put', 'PUT_RESPONSE', { key: Buffer.from('key5') }],
    ['getRange', 'GETKEYRANGE_RESPONSE'],
    ['getNext', 'GETNEXT_RESPONSE',
     { key: Buffer.from('key1') }, { key: Buffer.from('key2') }],
    ['getPrevious', 'GETPREVIOUS_RESPONSE',
     { key: Buffer.from('key1') }, { key: Buffer.from('key') }],
    ['delete', 'DELETE_RESPONSE', { dbVersion: newVersion, }],
    ['noop', 'NOOP_RESPONSE'],
    ['flush', 'FLUSH_RESPONSE'],
    ['getLog', 'GETLOG_RESPONSE'],
    ['setClusterVersion', 'SETUP_RESPONSE'],
    ['setClusterVersionTo0', 'SETUP_RESPONSE'],
];

function requestsLauncher(request, client, optionsA) {
    let pdu;
    let tag;

    const options = optionsA || {};

    switch (request) {
    case 'noop':
        pdu = new kinetic.NoOpPDU(sequence, connectionID, clusterVersion);
        break;
    case 'put':
        tag = crypto
            .createHmac('sha1', 'asdfasdf').update(chunk).digest();
        pdu = new kinetic.PutPDU(
            sequence, connectionID, clusterVersion, options.key || key,
            chunk.length, tag, options);
        break;
    case 'get':
        pdu = new kinetic.GetPDU(
            sequence, connectionID, clusterVersion, key);
        break;
    case 'getVersion':
        pdu = new kinetic.GetVersionPDU(
            sequence, connectionID, clusterVersion, key);
        break;
    case 'getRange':
        pdu = new kinetic.GetKeyRangePDU(sequence, connectionID, clusterVersion,
                                         startKey, endKey, maxRet, options);
        break;
    case 'delete':
        pdu = new kinetic.DeletePDU(
            sequence, connectionID,
            clusterVersion, key, options);
        break;
    case 'flush':
        pdu = new kinetic.FlushPDU(sequence, connectionID, clusterVersion);
        break;
    case 'getLog':
        pdu = new kinetic.GetLogPDU(
            sequence, connectionID, clusterVersion, [0, 1, 2, 4, 5, 6]);
        break;
    case 'setClusterVersion':
        pdu = new kinetic.SetClusterVersionPDU(
            sequence, connectionID, clusterVersion, 1234);
        clusterVersion = 1234;
        break;
    case 'setClusterVersionTo0':
        pdu = new kinetic.SetClusterVersionPDU(
            sequence, connectionID, clusterVersion, 0);
        clusterVersion = 0;
        break;
    case 'getNext':
        pdu = new kinetic.GetNextPDU(
            sequence, connectionID, clusterVersion, options.key || key);
        break;
    case 'getPrevious':
        pdu = new kinetic.GetPreviousPDU(
            sequence, connectionID, clusterVersion, options.key || key);
        break;
    default:
        break;
    }

    client.write(pdu.read());
    if (request === 'put') {
        client.write(chunk);
    }

    sequence++;
}

function checkTest(request, requestResponse, options, optRes, done) {
    const client = net.connect(PORT, HOST);

    client.on('data', function heandleData(data) {
        let pdu;
        let chunkResponse;

        try {
            pdu = new kinetic.PDU(data);
        } catch (e) {
            return done(e);
        }

        if (pdu.getMessageType() === null ||
            kinetic.getOpName(pdu.getMessageType()) !== requestResponse) {
            connectionID = pdu.getConnectionId();
            clusterVersion = pdu.getClusterVersion();
            requestsLauncher(request, client, options, done);
        } else {
            assert.deepEqual(pdu.getStatusCode(),
                kinetic.errors.SUCCESS);
            assert.deepEqual(
                pdu.getMessageType(), kinetic.ops[requestResponse]);

            if (request === 'get'
                || request === 'getNext'
                || request === 'getPrevious') {
                chunkResponse =
                          data.slice(data.length - pdu.getChunkSize());
                assert.deepEqual(chunkResponse, chunk);
                assert.deepEqual(pdu.getKey(), optRes.key);
            }
            client.end();

            done();
        }
    });
}

function checkIntegrity(requestArr) {
    const request = requestArr[0];
    const response = requestArr[1];
    const options = requestArr[2];
    const optRes = requestArr[3];
    describe(`Assess ${request} and its response ${response}`, () => {
        it(`Chunk and ${request} protobufMessage should be preserved`,
           (done) => { checkTest(request, response, options, optRes, done); });
    });
}

requestsArr.forEach(checkIntegrity);
