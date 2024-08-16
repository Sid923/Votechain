import pickle
import os
import matplotlib
matplotlib.use('MacOSX')  # You can also try 'Qt5Agg' or 'MacOSX' depending on your system
import matplotlib.pyplot as plt
import networkx as nx

BLOCKCHAIN_FILE = 'temp/blockchain.dat'

def load_blockchain():
    if os.path.exists(BLOCKCHAIN_FILE):
        with open(BLOCKCHAIN_FILE, 'rb') as f:
            try:
                blockchain = pickle.load(f)
                if not isinstance(blockchain, list):
                    blockchain = [blockchain]
                return blockchain
            except EOFError:
                return []
    return []

def visualize_blockchain(blockchain):
    G = nx.DiGraph()

    for block in blockchain:
        block_label = f"Block {block.height}\nHash: {block.hash[:6]}...\nVotes: {block.number_of_votes}"
        G.add_node(block.height, label=block_label)

        if block.height > 0:  # Skip genesis block
            G.add_edge(block.height - 1, block.height)

    pos = nx.spring_layout(G)
    labels = nx.get_node_attributes(G, 'label')
    nx.draw(G, pos, labels=labels, with_labels=True, node_size=3000, node_color="lightblue", font_size=10)
    plt.title('Blockchain Visualization')
    plt.show()

if __name__ == "__main__":
    blockchain = load_blockchain()
    if blockchain:
        visualize_blockchain(blockchain)
    else:
        print("Blockchain is empty or not found.")