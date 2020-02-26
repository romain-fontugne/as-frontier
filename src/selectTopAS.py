# Select nodes in the graph belong to the largest ASes
import json
import sys
import networkx as nx
from collections import Counter

NB_SELECTED_AS = 5

labels_fname = sys.argv[1]
graph_fname = sys.argv[2]

# Read the graph
G = nx.read_adjlist(graph_fname)

# Reading labels
gt_labels = {}
for line in open(labels_fname, 'r'):
    col = line.split(',')
    # if col[1] == 'NaN':
        # continue

    gt_labels[col[0]] = col[1]

# Find largest ASes
nb_nodes = Counter()
nb_nodes.update(gt_labels.values())

top_asn = nb_nodes.most_common(NB_SELECTED_AS)
print(f'Selected ASes: {top_asn}')

# Find corresponding nodes 
selected_asn = [asn for asn, count in top_asn]
selected_asn.append('NaN')
selected_nodes = [node for node, asn in gt_labels.items() if asn in selected_asn]

subgraph = G.subgraph(selected_nodes)

cc = list(nx.connected_components(subgraph))
largest_cc = [0,'']
for c in cc:
    if len(c) > largest_cc[0]:
        largest_cc = (len(c), c)
if len(cc) > 1:
    print(f'The graph has now {len(cc)} connected components')
    print([len(c) for c in cc])

nx.write_adjlist(
        subgraph.subgraph(largest_cc[1]), 
        graph_fname.replace(".txt", f"_top{NB_SELECTED_AS}AS.txt")
        )
    
