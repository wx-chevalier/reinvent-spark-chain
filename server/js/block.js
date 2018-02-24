const sha256 = require('crypto-js/sha256')

class Block {
    constructor(index, previousHash, data, difficulty) {
        this.index = index
        this.previousHash = previousHash
        this.data = data
        this.timestamp = new Date()
        this.difficulty = difficulty
        this.nonce = 0
        
        this.mineUsingProofOfWork()
    }

    generateHash() {
        return sha256(this.index + this.previousHash + JSON.stringify(this.data) + this.timestamp + this.nonce).toString()
    }

    mineUsingProofOfWork() {
        this.hash = this.generateHash()

        while (!(/^0*$/.test(this.hash.substring(0, this.difficulty)))) {
            this.nonce++
            this.hash = this.generateHash()
        }
    }
}

module.exports = Block