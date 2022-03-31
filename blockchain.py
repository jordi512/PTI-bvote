import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

 import requests
from flask import Flask, jsonify, request

# python3 -m pip install pycryptodome

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.current_validator=0
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100,self.current_transactions)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def valid_transaction(self, transaction):
        decipher_rsa = PKCS1_OAEP.new(transaction['sender'])
        dec_data = decipher_rsa.decrypt(transaction['signature'])
        if dec_data!='signature' :
            return false
        if not self.exists_transaction(transaction):
            return false
        if self.repeated_transaction(transaction['sender']):
            return false
        return true

    def valid_block(self, block):
        if not self.valid_proof(block['proof']):
            return false
        if self.repeated_block(block):
            return false
        for trans in block['transactions']:
            if not self.valid_transaction(trans):
                return false
        return true

    def repeated_block(self, block):
        for b in self.chain:
            if b==block return true
        return false

    def repeated_transaction(self, sender):
        for block in self.chain:
            transactions=block['transactions']
            for trans in transactions:
                if trans['sender']==sender:
                    return true
        return false

    def exists_transaction(self,transaction):
        ref=transaction['ref']
        if transaction in self.current_transactions:
            return true
        for block in self.chain:
            transactions=block['transactions']
            for trans in transactions:
                if hashlib.sha256(trans).hexdigest()==ref:
                    return true
        return false

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            #if not self.valid_proof(last_block['proof'], block['proof'], last_block['previous_hash']):
            if not self.valid_proof(last_block['proof'], block['proof'], block['previous_hash']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash, transactions):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        temp=self.current_transactions
        self.clean_transactions(transactions);
        if not valid_block(block):
            self.current_transactions=temp
            return {}
        self.chain.append(block)
        return block

    def clean_transactions(self, transactions):
        self.current_transactions = [x for x in self.current_transactions if x not in transactions]

    def new_transaction(self, sender, recipient, ref, signature):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param ref: Refference to a previous transaction where the node received the possibility to vote
        :return: The index of the Block that will hold this transaction
        """
        transaction={
            'sender': sender,
            'recipient': recipient,
            'ref': ref,
            'signature': signature,
        }
        if self.valid_transaction(transaction):
            self.current_transactions.append(transaction)

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof

        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    def valid_proof(self, proof):
        return proof==self.current_validator


# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
        order=0,
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash,blockchain.current_transactions)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'ref', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['ref'], values['signature'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    #for node in nodes:
    #    blockchain.register_node(node)
    blockchain.register_node(nodes)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

@app.route('/nodes/list', methods=['GET'])
def getNodes():
    response={'nodes':str(blockchain.nodes)}
    return jsonify(response), 200

@app.route('/validate', methods=['GET'])
def validate():
    if blockchain.valid_chain(blockchain.chain):
        return "The stored chain is valid\n", 200
    else:
        return "The stored chain is not valid\n", 200

@app.route('/nodes/manipulate', methods=['POST'])
def manipulate():
    blockchain.chain[0]['proof']=17
    return jsonify({'Message':"Chain manipuled."}), 201

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)
