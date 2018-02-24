# simpleblockchain.js - My first simple blockchain

One time install:

    $ npm install 

to run use:

    $ HTTP_PORT=3001 P2P_PORT=6001 npm start
    $ HTTP_PORT=3002 P2P_PORT=6002 PEERS=ws://localhost:6001 npm start


some commands:

	a) get blocks
	$ GET http://localhost:3001/blocks

	b) createblock
	$ POST http://localhost:3003/mineBlock
	$ BODY {"data":"Test Block Data"}

	c) get peers
	$ GET http://localhost:3001/peers

	
inspired by
[A blockchain in 200 lines of code](https://medium.com/@lhartikk/a-blockchain-in-200-lines-of-code-963cc1cc0e54#.dttbm9afr5)
by Lauri Hartikka