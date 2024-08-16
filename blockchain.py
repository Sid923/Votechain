from hashlib import sha256
from time import time
import pickle
import csv
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
import base64
from flask import session
from utils import verification as ver

PROJECT_PATH = 'D:\Jay\hh\Trial'
DIFFICULTY = 4

class Blockchain:
    chain = []
    adminpriv, adminpub = None, None

    def __init__(self):
        self.addGenesis()
        self.adminpriv, self.adminpub = self.rsakeys()
        print('Blockchain initialized')

    @staticmethod
    def genesis():
        gen = Block(0, "Let the real democracy rule!!", 0, sha256(str("Let the real democracy rule!!").encode('utf-8')).hexdigest(), DIFFICULTY, time(), '', 0, 'Errrrrorrr')
        return gen

    @staticmethod
    def addGenesis():
        genesisblock = Blockchain.genesis()
        genesisblock.nonce = genesisblock.pow()
        genesisblock.hash = genesisblock.calcHash()
        Blockchain.chain.append(genesisblock)

        with open('temp/Blockchain.dat', 'ab') as genfile:
            pickle.dump(genesisblock, genfile)
        print("Genesis block added")

    @staticmethod
    def display():
        try:
            with open('temp/blockchain.dat', 'rb') as blockfile:
                while True:
                    try:
                        data = pickle.load(blockfile)
                        print("Block Height: ", data.height)
                        print("Data in block: ", data.data)
                        print("Number of votes: ", data.number_of_votes)
                        print("Merkle root: ", data.merkle)
                        print("Difficulty: ", data.DIFFICULTY)
                        print("Time stamp: ", data.timeStamp)
                        print("Previous hash: ", data.prevHash)
                        print("Block Hash: ", data.hash)
                        print("Nonce: ", data.nonce, '\n\t\t|\n\t\t|')
                    except EOFError:
                        break
        except FileNotFoundError:
            print("\n.\n.\n.\n<<<File not found!!>>>")

    @staticmethod
    def update_votepool():
        try:
            with open('temp/votefile.csv', 'w+') as votefile:
                pass
        except Exception as e:
            print("Some error occurred: ", e)
        return "Done"

    def is_votepool_empty(self):
        my_path = PROJECT_PATH + '/temp/votefile.csv'
        if os.path.isfile(os.path.expanduser(my_path)) and os.stat(os.path.expanduser(my_path)).st_size == 0:
            return True
        return False

    @classmethod
    def verify_chain(cls):
        index, conclusion = ver.sync_blocks(cls.chain)
        if not conclusion:
            error_msg = f"""+-----------------------------------------+
|                                         |
| Somebody messed up at Block number - {index} |
|                                         |
+-----------------------------------------+"""
            raise Exception(error_msg)
        return True

    @staticmethod
    def rsakeys():
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return private_key, public_key
    
    @staticmethod
    def encrypt(data, public_key):
        key = RSA.import_key(public_key.encode('utf-8'))
        cipher = PKCS1_v1_5.new(key)
        encrypted_data = cipher.encrypt(data.encode('utf-8'))
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        print(f"Encrypted Data (Base64): {encrypted_data_b64}")
        print(f"Encrypted Data Length: {len(encrypted_data_b64)}")
        return encrypted_data_b64

    @staticmethod
    def decrypt(data, private_key):
        key = RSA.import_key(private_key.encode('utf-8'))
        data_b64 = base64.b64decode(data)
        print(f"Data (Base64 Decoded): {data_b64}")
        print(f"Data Length after Base64 Decoding: {len(data_b64)}")
        cipher = PKCS1_v1_5.new(key)
        sentinel = get_random_bytes(16)
        try:
            decrypted_data = cipher.decrypt(data_b64, sentinel)
            print(f"Decrypted Data: {decrypted_data.decode('utf-8')}")
            return decrypted_data.decode('utf-8')
        except ValueError as e:
            print(f"Decryption failed: {e}")
            return None

    @staticmethod
    def importKey(key_str):
        print(f"Key String: {key_str}")
        return RSA.import_key(key_str)
    
    @staticmethod
    def debug_key_import(key_str):
        try:
            key = RSA.import_key(key_str.encode('utf-8'))
            print("Key imported successfully")
            return key
        except ValueError as e:
            print(f"ValueError: {e}")
            print(f"Key string: {key_str[:100]}...")  # Print the first 100 characters of the key for debugging
            return None

    @staticmethod
    def exportKey():
        return RSA.generate(2048).export_key().decode('utf-8')

class Block:
    def __init__(self, height=0, data='WARNING = SOME ERROR OCCURED', votes=0, merkle='0', DIFFICULTY=0, time=0, prevHash='0', pow=0, hash='ERROR'):
        self.height = height
        self.data = data
        self.number_of_votes = votes
        self.merkle = merkle
        self.DIFFICULTY = DIFFICULTY
        self.timeStamp = time
        self.prevHash = prevHash
        self.nonce = pow
        self.hash = hash

    def pow(self, zero=DIFFICULTY):
        self.nonce = 0
        while self.calcHash()[:zero] != '0' * zero:
            self.nonce += 1
        return self.nonce

    def calcHash(self):
        return sha256((str(self.data) + str(self.nonce) + str(self.timeStamp) + str(self.prevHash)).encode('utf-8')).hexdigest()

    @staticmethod
    def loadvote():
        votelist = []
        votecount = 0
        try:
            with open('temp/votefile.csv', mode='r') as votepool:
                csvreader = csv.reader(votepool)
                for row in csvreader:
                    votelist.append({'Voter Public Key': row[0], 'Vote Data': row[1], 'Key': row[2]})
                    votecount += 1
            return votelist, votecount
        except (IOError, IndexError) as e:
            print(f"Error occurred while loading votes: {e}")
            return [], 0  # Return default values in case of an error
        finally:
            print("data loaded in block")
            print("Updating unconfirmed vote pool...")
            print(Blockchain.update_votepool())

    def merkleRoot(self):
        return 'congrats'

    def mineblock(self):
        self.height = len(Blockchain.chain)
        self.data, self.number_of_votes = self.loadvote()
        self.merkle = self.merkleRoot()
        self.DIFFICULTY = DIFFICULTY
        self.timeStamp = time()
        self.prevHash = Blockchain.chain[-1].calcHash()
        self.nonce = self.pow()
        self.hash = self.calcHash()
        Blockchain.chain.append(self)
        return self

class vote:
    def __init__(self, hidden_voter_id, candidate_id, voter_public_key):
        self.hiddenvoterid = hidden_voter_id
        self.candidate = candidate_id
        self.voterpubkey = voter_public_key
        self.rsa_key = Blockchain.importKey(voter_public_key)  # Ensure this is correct
        self.votedata = Blockchain.encrypt(self.candidate, self.voterpubkey)  # Encrypting candidate ID

    def verify(self):
        try:
            # Decrypt using RSA
            decrypted_id = Blockchain.decrypt(self.votedata, session.get('private_key'))
            if decrypted_id is None:
                return False
            print(f"Decrypted Voter ID: {decrypted_id}")

        except Exception as e:
            print(f"Decryption failed: {e}")
            return False

        try:
            with open('temp/VoterID_Database.txt', 'r') as f:
                contents = f.readlines()
            contents = [x.strip() for x in contents]
        except FileNotFoundError:
                contents = []

        if decrypted_id in contents:
            return False

        with open('temp/VoterID_Database.txt', 'a') as f:
            f.write(decrypted_id + '\n')

        return True

    def save_vote(self):
        with open('temp/votefile.csv', 'a+', newline='') as votefile:
            writer = csv.writer(votefile)
            writer.writerow([self.hiddenvoterid, self.votedata])
        print("Vote casted successfully")

        blockchain_file = 'temp/blockchain.dat'
        blockchain = []

        # Load existing blockchain from file if it exists
        if os.path.exists(blockchain_file):
            with open(blockchain_file, 'rb') as f:
                try:
                    blockchain = pickle.load(f)
                    if not isinstance(blockchain, list):
                         blockchain = [blockchain]
                except EOFError:
                    blockchain = []

        prev_hash = blockchain[-1].hash if blockchain else '0'
        new_block = Block(len(blockchain), {'voter_id': self.hiddenvoterid, 'candidate_id': self.candidate}, prev_hash)
        new_block.mineblock()

        blockchain.append(new_block)

        with open(blockchain_file, 'wb') as f:
            pickle.dump(blockchain, f)

    @classmethod
    def get_votecount(cls):
        return cls.count