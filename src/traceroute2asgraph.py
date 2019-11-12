import sys
import os
import json
import networkx as nx
import argparse
import bdrmapit
from matplotlib import pylab as plt
from collections import defaultdict
import numpy as np

sys.path.append("../ip2asn/")
import ip2asn
class Traceroute2ASGraph(object):

    """Make AS graph from a raw traceroute data."""

    def __init__(self, fnames, target_asn, ip2asn_db="data/rib.20190301.pickle", 
            ip2asn_ixp="data/ixs_201901.jsonl", output_directory="graphs/test/"):
        """fnames: traceroutes filenames
        target_asn: keep only traceroutes crossing this ASN, None to get all traceroutes
        ip2asn_db: pickle file for the ip2asn module
        ip2asn_ixp: IXP info for ip2asn module"""
    
        self.fnames = fnames
        if target_asn:
            self.target_asn = int(target_asn)
        else:
            self.target_asn = None
        self.i2a = ip2asn.ip2asn(ip2asn_db, ip2asn_ixp)
        self.graph = None
        self.vinicity_asns = defaultdict(set)
        self.routers_asn = {}
        self.observed_asns = set()

        if not output_directory.endswith('/'):
            output_directory+='/'

        self.fname_prefix = output_directory
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)
        # self.fname_prefix = "graphs/test/bad_expert_"

        self.periphery_size = 2


    def find_as_paths(self, fi):
        """Read traceroute file and return AS paths for matching traceroutes"""

        for line in fi:
            res = json.loads(line)
            if "dst_addr" not in res:
                continue
            # print(res)
            as_path = {"dst": res["dst_addr"], "path": []}
            is_target_asn = self.target_asn is None
            for hop in res["result"]:
                # ignore errors, look only at the first result
                if "error" in hop:
                    continue
                trials = [t for t in hop["result"] if "from" in t]
                if not trials:
                    continue
                trial = trials[0]

                if as_path["path"] and trial["from"] == as_path["path"][-1][0]:
                    continue

                node =  (trial["from"], self.i2a.ip2asn(trial["from"]))
                as_path["path"].append(node)
                if as_path["path"][-1][1] == self.target_asn:
                    is_target_asn = True

            if is_target_asn:
                # Trim the AS path
                as_path["path"] = self.trim_as_path(as_path["path"])

                # Keep track of seen ASNs
                for (ip, asn) in as_path["path"]:
                    if asn>0:
                        self.observed_asns.add(asn)

                yield as_path
                
    def trim_as_path(self, path):
        """Keep only nodes that are periphery_size hops from the target ASN"""

        as_path = [x[1] for x in path]
        try:
            first = as_path.index(self.target_asn)
            last = list(reversed(as_path)).index(self.target_asn)+1

            start = 0
            if first > self.periphery_size:
                start = first - self.periphery_size

            end = len(as_path)-1
            if last + self.periphery_size < end:
                end = last + self.periphery_size

        except:
            print(as_path)

        return path[start:end+1]

    def add_path_to_graph(self, path):
        """Add AS path to the graph and label obvious nodes"""

        self.graph.add_path([hop[0] for hop in path["path"]])
        for i, (hop_ip, hop_asn) in enumerate(path["path"][1:-1]):
            self.routers_asn[hop_ip] = [hop_asn]
            self.vinicity_asns[hop_ip].add(hop_asn)
            self.vinicity_asns[hop_ip].add(path["path"][i][1])
            self.vinicity_asns[hop_ip].add(path["path"][i+2][1])
        
        # add the destination IP addr if it responded
        if len(path["path"]) and path["path"][-1][0] == path["dst"] and path["path"][-1][1] > 0:
            self.vinicity_asns[path["path"][-1][0]].add(path["path"][-1][1])
            self.routers_asn[path["path"][-1][0]] = [path["path"][-1][1]]

    def save_graphs(self, expert_confidence):
        """Save the graph on disk.
        
        expert_confidence indicate the node that should be labelled. 
        expert_confidence=1 means that only IPs with surrounded by IPs of the 
        same AS are labelled (strict expert).
        expert_confidence=0 will default to the simple IP to AS mapping for all
        IPs found.
        expert_confidence=None gives multiple labels corresponding to all surrounding
        IPs."""

        unique_asns = list(self.observed_asns)
        node_labels = list(self.graph.nodes())

        expert = np.zeros((len(unique_asns), len(node_labels)))
        if expert_confidence == 0:
            asmap = self.routers_asn
        else:
            asmap = self.vinicity_asns

        for ip, asns in asmap.items(): 
            idx_ip = node_labels.index(ip)
            confidence = 1.0/len(asns)
            for asn in asns:
                if asn <= 0:
                    continue

                idx_asn = unique_asns.index(asn)

                if expert_confidence is None:
                    expert[idx_asn, idx_ip] = confidence
                else:
                    if confidence >= expert_confidence:
                        expert[idx_asn, idx_ip] = 1.0

        # Save graph to files
        # don't store the entire matrix, use a compact format
        # np.savetxt(self.fname_prefix+"ip_graph.txt", nx.to_numpy_array(self.graph), fmt='%s')
        nx.write_adjlist(self.graph, self.fname_prefix+"ip_graph.txt")
        if expert_confidence == 1.0:
           fname = "expert_strict.txt"
        elif expert_confidence == 0.0:
            fname = "expert_loose.txt"
        else:
            fname = "expert_weighted.txt"

        np.savetxt(self.fname_prefix+fname, expert, fmt='%s')
        np.savetxt(self.fname_prefix+"node_labels.txt", node_labels, fmt='%s')
        np.savetxt(self.fname_prefix+"asns_labels.txt", unique_asns, fmt='%s')

    def bdrmapit_results(self):
        """Output Bdrmapit results for the computed graph"""

        ips = set(self.graph.nodes())
        print('Loading bdrmapit results...')
        bm = bdrmapit.bdrmapit(filter_ips=ips)

        print('Output results...')
        with open(self.fname_prefix+'bdrmapit.csv', 'w') as fi:
            for ip in ips:
                fi.write('{}, {}, {}\n'.format( ip, bm.ip2asn(ip), self.routers_asn[ip]))

    def process_files(self):
        """Read all files, make the graph, and save it on disk.
        """

        self.graph = nx.Graph()
        for fname in self.fnames:
            with open(fname, "r") as fi:
                for path in self.find_as_paths(fi):
                    self.add_path_to_graph(path)

        # nx.set_node_attributes(self.graph, self.vinicity_asns, "ASN")

        # node_labels = self.graph.nodes()
        # adj_matrix = nx.to_numpy_array(self.graph)
        # print(adj_matrix)
        # print(node_labels)
        # print(self.vinicity_asns)

        plot = False
        if plot:
            # Plot graph
            plt.figure(figsize=(20,12))
            plt.axis('off')
            plt.grid(False)
            options = {
                'node_color': 'black',
                'node_size': 150,
                'line_color': 'grey',
                'linewidths': 0,
                'width': 0.1,
            }
            pos = nx.drawing.layout.kamada_kawai_layout(self.graph)
            nx.draw_networkx(self.graph, pos, **options)
            nx.draw_networkx_nodes(self.graph,pos,
                        nodelist=self.vinicity_asns.keys(),
                        node_color='r',
                        node_size=150)

            plt.savefig(self.fname_prefix+"graph_with_ips.pdf")
            # plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Make AS graph from raw traceroute data')
    parser.add_argument('--target-asn', 
                    help='keep only traceroute crossing this ASN')
    parser.add_argument('traceroutes', nargs='+',
                    help='traceroutes files (json format)')
    parser.add_argument('output', help='output directory')

    args = parser.parse_args()

    ttag = Traceroute2ASGraph(args.traceroutes, args.target_asn, output_directory=args.output)
    ttag.process_files()

    # Save graph to files
    ttag.save_graphs(expert_confidence=0.0)
    ttag.save_graphs(expert_confidence=1.0)
    ttag.save_graphs(expert_confidence=None)

    # Save corresponding bdrmapit results
    ttag.bdrmapit_results()
