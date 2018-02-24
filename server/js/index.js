const Blockchain = require('./blockchain')
const Block = require('./block')
const initialPeers = process.env.PEERS ? process.env.PEERS.split(',') : [];
const blockchain = new Blockchain()

blockchain.connectToPeers(initialPeers);
blockchain.initHttpServer();
blockchain.initP2PServer();