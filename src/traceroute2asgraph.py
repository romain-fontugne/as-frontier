import argparse
from itertools import chain
import json
import os
import re
import sys
from collections import defaultdict

import networkx as nx
import numpy as np

sys.path.append("../ip2asn/")
import bdrmapit
import ip2asn

# https://en.wikipedia.org/wiki/Private_network
priv_lo = re.compile("^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
priv_24 = re.compile("^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
priv_20 = re.compile("^192\.168\.\d{1,3}.\d{1,3}$")
priv_16 = re.compile("^172.(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$")

def isPrivateIP(ip):
    return priv_lo.match(ip) or priv_24.match(ip) or priv_20.match(ip) or priv_16.match(ip)



class Traceroute2ASGraph(object):

    """Make AS graph from a raw traceroute data."""

    def __init__(self, fnames, target_asns, ip2asn_db="data/rib.20190301.pickle",
                 ip2asn_ixp="data/ixs_201901.jsonl", output_directory="graphs/test/",
                 af=4):
        """fnames: traceroutes filenames
        target_asns: output graphs for these ASNs
        ip2asn_db: pickle file for the ip2asn module
        ip2asn_ixp: IXP info for ip2asn module"""

        self.fnames = fnames
        self.target_asns = [int(asn) for asn in target_asns.split(',')]
        self.i2a = ip2asn.ip2asn(ip2asn_db, ip2asn_ixp)
        self.graph = nx.Graph()
        self.vinicity_asns = defaultdict(set)
        self.routers_asn = {}
        self.ttls = defaultdict(list)
        self.sizes = defaultdict(list)
        self.af = af
        self.output_directory = output_directory

        if not self.output_directory.endswith('/'):
            self.output_directory += '/'

        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        self.periphery_size = 2

    def read_traceroute_file(self, fi):
        """Read traceroute file and return AS paths for matching traceroutes"""

        for line in fi:
            res = json.loads(line)

            if "dst_addr" not in res:
                continue

            # Filter v4/v6 addresses
            if ((':' in res['dst_addr'] and self.af == 4) 
                    or ('.' in res['dst_addr'] and self.af == 6)): 
                continue

            as_path = {"dst": res["dst_addr"], "path": []}
            dst_asn = self.i2a.ip2asn(res["dst_addr"])

            # Add the probe if we know its address
            if "from" in res and res["from"] != "" and not isPrivateIP(res['from']):
                node = {"ip":res["from"], "asn":self.i2a.ip2asn(res["from"]), "ttl":255, "size":0}
                as_path["path"].append(node)

            for hop in res["result"]:
                # ignore errors, look only at the first result
                if "error" in hop:
                    continue

                trials = [t for t in hop["result"] if "from" in t and not isPrivateIP(t["from"])]
                if not trials:
                    continue
                trial = trials[0]

                if as_path["path"] and trial["from"] == as_path["path"][-1]["ip"]:
                    continue

                node = {"ip": trial["from"], "asn": self.i2a.ip2asn(trial["from"]), "ttl": trial["ttl"], "size": trial["size"]}
                as_path["path"].append(node)

            # ignore path with a single router
            if len(as_path["path"]) < 2:
                continue

            # Add the destination node if it didn't respond
            if res["dst_addr"] != as_path["path"][0]:
                node = {"ip": res["dst_addr"], "asn": dst_asn, "ttl": as_path["path"][-1]['ttl'], "size": 0}
                as_path["path"].append(node)


            # Force dst node to the strict expert by adding the last router to 
            # in the same ASN
            if as_path["path"][-2]["asn"] != dst_asn:
                as_path["path"][-2]["asn"] = dst_asn

            yield as_path

    def extract_subgraph(self, asn):
        """Extract the subgraph for the given asn"""

        # Find all nodes related to the asn
        asn_nodes = {node: data for node, data in self.graph.nodes(data=True) 
                if data['asn']==asn}

        # Find all neighboring_nodes
        neighbor_nodes = {neighbor: self.graph.nodes[neighbor] 
                for node in asn_nodes
                    for neighbor in self.graph.neighbors(node)}

        # Find all core nodes of the neighboring asns
        neighbor_asns = set([data['asn'] for data in neighbor_nodes.values()]) 
        neighbor_nodes_core = {node: data for node, data in self.graph.nodes(data=True) 
                if data['asn'] in neighbor_asns and data['core']}

        # Get the subgraph
        subgraph_nodes = chain(asn_nodes.keys(), neighbor_nodes.keys(), neighbor_nodes_core.keys())
        subgraph = self.graph.subgraph(subgraph_nodes)
        
        return subgraph

    def find_core_nodes(self):
        """Find nodes that are surronded only by nodes from the same AS"""

        for node, data in self.graph.nodes(data=True):
            neighbors_asn = set([self.graph.nodes[neighbor]['asn'] 
                    for neighbor in self.graph.neighbors(node)])

            if data['size'] == 0:
                # Atlas probes and destination IPs are core nodes
                data['core'] = True
            if len(neighbors_asn) == 1 and data['asn'] in neighbors_asn:
                data['core'] = True
            else:
                data['core'] = False


    def add_path_to_graph(self, path):
        """Add AS path to the graph and label obvious nodes"""

        ip_path = [hop["ip"] for hop in path["path"]]
        if len(ip_path) < 2:
            return

        nx.add_path(self.graph, ip_path)

        # Add nodes metadata
        for hop in path["path"]:
            if 'asn' not in self.graph.nodes[hop["ip"]]:
                self.graph.nodes[hop["ip"]]['ttl'] = []
                self.graph.nodes[hop["ip"]]['size'] = []
                self.graph.nodes[hop["ip"]]['asn'] = hop["asn"]

            self.graph.nodes[hop["ip"]]['ttl'].append(hop["ttl"])
            self.graph.nodes[hop["ip"]]['size'].append(hop["size"])

    def save_graph(self, graph):
        """Save the IP graph and graph labels to disk.

        The graph file format is networkx adjency list"""

        nx.write_adjlist(graph, self.fname_prefix+"ip_graph.txt")

        node_labels = list(graph.nodes())

        np.savetxt(self.fname_prefix+"node_labels.txt", node_labels, fmt='%s')

    def save_graph_labels(self, graph):
        """Output bdrmapit, ip2asn (router and vinicity), TTLs labels for the 
        given graph"""

        ips = dict(graph.nodes(data=True))
        print('Loading bdrmapit results...')
        bm = bdrmapit.bdrmapit(filter_ips=ips.keys())

        print('Output results...')
        with open(self.fname_prefix+'labels.csv', 'w') as fi:
            for ip, data in ips.items():
                neighbors_asn = set([graph.nodes[neighbor]['asn'] 
                        for neighbor in graph.neighbors(ip)])
                fi.write('{}, {}, {}, {}, {}, {}\n'.format(
                    ip, bm.ip2asn(ip), data['asn'], list(neighbors_asn), 
                    np.mean(data['ttl']), np.mean(data['size'])))

    def plot_graph(self, graph):
        """Plot the given graph"""

        from matplotlib import pylab as plt

        plt.figure(figsize=(20, 12))
        plt.axis('off')
        plt.grid(False)
        options = {
            'node_color': 'black',
            'node_size': 150,
            'line_color': 'grey',
            'linewidths': 0,
            'width': 0.1,
        }
        pos = nx.drawing.layout.kamada_kawai_layout(graph)
        nx.draw_networkx(graph, pos, **options)
        nx.draw_networkx_nodes(graph, pos,
                                nodelist=self.vinicity_asns.keys(),
                                node_color='r',
                                node_size=150)

        plt.savefig(self.fname_prefix+"graph_with_ips.pdf")


    def process_files(self):
        """Read all files, make the graph, and save it on disk.
        """

        # Constuct the global graph from all files
        print('Reading traceroute data...')
        for fname in self.fnames:
            with open(fname, "r") as fi:
                for path in self.read_traceroute_file(fi):
                    self.add_path_to_graph(path)

        print('Finding core nodes...')
        self.find_core_nodes()

        for asn in self.target_asns:
            self.fname_prefix = self.output_directory+"AS{}/".format(asn)
            if not os.path.exists(self.fname_prefix):
                os.makedirs(self.fname_prefix)

            print('Finding subgraph (AS{})...'.format(asn))
            subgraph = self.extract_subgraph(asn)
            print('Saving subgraph (AS{})...'.format(asn))
            self.save_graph(subgraph)
            print('Saving labels (AS{})...'.format(asn))
            self.save_graph_labels(subgraph)

            plot = False
            if plot:
                self.plot_graph(subgraph)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Make AS graph from raw traceroute data')
    parser.add_argument('--target-asns',
                help='Comma separated list of ASNs, output graphs only for these asns')
    parser.add_argument('traceroutes', nargs='+',
                        help='traceroutes files (json format)')
    parser.add_argument('output', help='output directory')

    args = parser.parse_args()

    ttag = Traceroute2ASGraph(
        args.traceroutes, args.target_asns, output_directory=args.output)
    ttag.process_files()


# Sanity check:
# All probes should be flagged as core node
