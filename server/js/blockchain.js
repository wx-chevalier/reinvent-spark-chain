const Block = require('./block')

const express = require("express")
const bodyParser = require('body-parser')
const WebSocket = require("ws")

const http_port = process.env.HTTP_PORT || 3001;
const p2p_port = process.env.P2P_PORT || 6001;
const difficulty = 2;
const MessageType = {
    QUERY_LATEST: 0,
    QUERY_ALL: 1,
    RESPONSE_BLOCKCHAIN: 2
};
var sockets = []

class Blockchain {
  constructor() {
    this.difficulty = difficulty
    this.chain = [this.createGenesisBlock()]
  }

  createGenesisBlock(){
    const index = 0
    const genesisData = "Genesis Block"
    const genesisBlock = new Block(index, null, genesisData, this.difficulty)

    return genesisBlock
  }

  getLastBlock() {
    return this.chain[this.chain.length - 1]
  }

  addBlock(data) {
    const index = this.getLastBlock().index + 1
    const difficulty = this.difficulty
    const previousHash = this.getLastBlock().hash
    if(data == null){
      console.log("Error: block data is null.")
      return;
    }

    const block = new Block(index, previousHash, data, difficulty)

    this.chain.push(block)
    console.log('Block added: ' + JSON.stringify(this.getLastBlock()));
  }

  isValidChain() {
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i]
      const previousBlock = this.chain[i - 1]

      if (currentBlock.hash !== currentBlock.generateHash()) {
        return false
      }

      if (currentBlock.index !== previousBlock.index + 1) {
        return false
      }

      if (currentBlock.previousHash !== previousBlock.hash) {
        return false
      }
    }
    return true
  }

  replaceChain(newBlocks){
    if (this.isValidChain(newBlocks) && newBlocks.length > this.chain.length) {
      console.log('Received blockchain is valid. Replacing current blockchain with received blockchain');
      this.chain = newBlocks;
      this.broadcast(this.responseLatestMsg());
    } else {
      console.log('Received blockchain invalid');
    }
  }


  initHttpServer(){
    var app = express();
    app.use(bodyParser.json());

    app.get('/blocks', (req, res) => res.send(JSON.stringify(this.chain)));
    app.post('/mineBlock', (req, res) => {
      this.addBlock(req.body.data);
      this.broadcast(this.responseLatestMsg());
      res.send();
    });
    app.get('/peers', (req, res) => {
      res.send(sockets.map(s => s._socket.remoteAddress + ':' + s._socket.remotePort));
    });
    app.post('/addPeer', (req, res) => {
      connectToPeers([req.body.peer]);
      res.send();
    });
    app.listen(http_port, () => console.log('Listening http on port: ' + http_port));
  }

  initP2PServer() {
    var server = new WebSocket.Server({port: p2p_port});
    server.on('connection', ws => this.initConnection(ws));
    console.log('listening websocket p2p port on: ' + p2p_port);
  }

  initConnection(ws){
    sockets.push(ws);
    this.initMessageHandler(ws);
    this.initErrorHandler(ws);
    this.write(ws, this.queryChainLengthMsg());
  }

  initMessageHandler(ws){
    ws.on('message', (data) => {
      var message = JSON.parse(data);
      console.log('Received message' + JSON.stringify(message));
      switch (message.type) {
        case MessageType.QUERY_LATEST:
        this.write(ws, this.responseLatestMsg());
        break;
        case MessageType.QUERY_ALL:
        this.write(ws, this.responseChainMsg());
        break;
        case MessageType.RESPONSE_BLOCKCHAIN:
        this.handleBlockchainResponse(message);
        break;
      }
    });
  };

  initErrorHandler(ws) {
    var closeConnection = (ws) => {
      console.log('connection failed to peer: ' + ws.url);
      sockets.splice(sockets.indexOf(ws), 1);
    };
    ws.on('close', () => closeConnection(ws));
    ws.on('error', () => closeConnection(ws));
  };


  connectToPeers(newPeers) {
    newPeers.forEach((peer) => {
      var ws = new WebSocket(peer);
      ws.on('open', () => this.initConnection(ws));
      ws.on('error', () => {
        console.log('connection failed')
      });
    });
  };

  handleBlockchainResponse(message){
    var receivedBlocks = JSON.parse(message.data).sort((b1, b2) => (b1.index - b2.index));
    var latestBlockReceived = receivedBlocks[receivedBlocks.length - 1];
    var latestBlockHeld = this.getLastBlock();
    if (latestBlockReceived.index > latestBlockHeld.index) {
      console.log('blockchain possibly behind. We got: ' + latestBlockHeld.index + ' Peer got: ' + latestBlockReceived.index);
      if (latestBlockHeld.hash === latestBlockReceived.previousHash) {
        console.log("We can append the received block to our chain");
        this.chain.push(latestBlockReceived);
        this.broadcast(this.responseLatestMsg());
      } else if (receivedBlocks.length === 1) {
        console.log("We have to query the chain from our peer");
        this.broadcast(this.queryAllMsg());
      } else {
        console.log("Received blockchain is longer than current blockchain");
        this.replaceChain(receivedBlocks);
      }
    } else {
      console.log('received blockchain is not longer than current blockchain. Do nothing');
    }
  }

  write(ws, message){
    ws.send(JSON.stringify(message));
  }

  broadcast(message){
    sockets.forEach(socket => this.write(socket, message));
  }

  queryChainLengthMsg () {
    return ({'type': MessageType.QUERY_LATEST});
  }
  queryAllMsg() {
    return ({'type': MessageType.QUERY_ALL});
  } 
  responseChainMsg() {
    return ({ 'type': MessageType.RESPONSE_BLOCKCHAIN, 'data': JSON.stringify(this.chain)});
  }
  responseLatestMsg() { return ({
    'type': MessageType.RESPONSE_BLOCKCHAIN,
    'data': JSON.stringify([this.getLastBlock()])});
  }
}

module.exports = Blockchain


