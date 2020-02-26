# Clean ip_graph.txt and labels.csv files
# Format of output file (labels_filtered.csv):
# ip,ground truth, BGP (loose expert), strict expert, bdrmapit
import json
import sys
import networkx as nx
from collections import defaultdict

if len(sys.argv)> 3:
    SIZE_DST_EXPANSION = int(sys.argv[2])
else: 
    SIZE_DST_EXPANSION = 1

target_asn = int(sys.argv[-1])
input_dir = '{}/AS{}/'.format(sys.argv[1], target_asn)

# Read the graph
G = nx.read_adjlist(input_dir+'ip_graph.txt')

# Reading labels
labels = {}
core_nodes = defaultdict(list)
all_dst_nodes = []
for line in open(input_dir+'labels.csv', 'r'):
    col = line.split(',')
    bgp = int(col[2])
    labels[col[0]] = bgp 

    # Compute strict expert
    neighbors_list = '['+(line.partition('[')[2]).rpartition(']')[0]+']'
    neighbors = set(json.loads(neighbors_list))
    if len(neighbors) == 1 and bgp in neighbors:
        core_nodes[bgp].append(col[0])

    # track destination nodes
    # TODO: track also destination nodes that responded
    if col[0].strip().endswith('.1') and float(col[-1]) == 0 :
        all_dst_nodes.append(col[0].strip())
    # elif col[0].strip().endswith('.1') and G.degree[col[0]] == 1:
        # all_dst_nodes.append(col[0].strip())

# filter useless nodes
cc = nx.connected_components(G)
final_nodes = []
cc_sizes = [] 
for component in cc:
    if any(labels[node] == target_asn for node in component):
        cc_sizes.append(len(component))
        final_nodes.extend(component)

print(f'Found {len(cc_sizes)} connected components')
print(f'Connected components sizes: {cc_sizes} ')

filteredgraph = nx.Graph(G.subgraph(final_nodes))
print(f'Number of edges in filtered graph: {filteredgraph.number_of_edges()}')

# Find dst nodes in the subgraph
dst_nodes = []
for n in all_dst_nodes:
    if n in filteredgraph:
        dst_nodes.append(n)
dst_nodes = set(dst_nodes)

# Expand destination nodes
for dnode in  dst_nodes: 
    neighbors = [n for n in G.neighbors(dnode) if n!=dnode]
    filteredgraph.remove_node(dnode)

    # generate cluster node
    cluster = [f'{dnode}_{i}' for i in range(SIZE_DST_EXPANSION)]
    
    # wire the component to previous neighbors
    for n0 in cluster:
        for n1 in neighbors:
            filteredgraph.add_edge(n0, n1)

### Rewiring 
# Connect dest and core nodes from the same ASN
asns = set(labels.values())
for asn in asns:
    # destination nodes
    asn_dnodes = [f'{n}_{i}' for n in dst_nodes if labels[n]==asn for i in range(SIZE_DST_EXPANSION)]
    # add core nodes
    asn_dnodes.extend([n for n in core_nodes[asn] if n in filteredgraph])
    for n0 in asn_dnodes:
        for n1 in asn_dnodes:
            if n0!=n1:
               filteredgraph.add_edge(n0,n1) 

print(f'Number of edges after rewiring: {filteredgraph.number_of_edges()}')

# Write connected components in different graphs
cc = nx.connected_components(filteredgraph)
for comp_id, component in enumerate(cc):
    # output filtered graph
    nx.write_adjlist(
            filteredgraph.subgraph(component), 
            input_dir+f"ip_graph_cc{comp_id}_filtered_expansion{SIZE_DST_EXPANSION}.txt"
            )

# output new labels file
fp = open(input_dir+f'labels_filtered_expansion{SIZE_DST_EXPANSION}.csv', 'w')
for line in open(input_dir+'labels.csv', 'r'):
    col = line.split(',')
    if col[0] in filteredgraph or col[0] in dst_nodes:
        # clean labels 
        bdrmapit = 'NaN' if col[1].strip()=='None' else col[1].strip()
        bgp = 'NaN' if int(col[2])==0 else int(col[2])

        # strict expert
        neighbors_list = '['+(line.partition('[')[2]).rpartition(']')[0]+']'
        neighbors = set(json.loads(neighbors_list))
        strict = bgp if len(neighbors) == 1 and bgp in neighbors else 'NaN'

        # ground truth
        gt = bdrmapit
        # destination nodes are set to their mapped ASN
        if gt=='NaN' and col[0].strip().endswith('.1') and float(col[-1]) == 0 :
            gt = bgp
        elif gt=='NaN' and col[0].strip().endswith('.1') and G.degree[col[0]] == 1 :
            gt = bgp

        if col[0] in dst_nodes:
            for i in range(SIZE_DST_EXPANSION):
                fp.write("{}_{},{},{},{},{}\n".format(col[0],i,gt,bgp,strict,bdrmapit))
        else:
            fp.write("{},{},{},{},{}\n".format(col[0],gt,bgp,strict,bdrmapit))


