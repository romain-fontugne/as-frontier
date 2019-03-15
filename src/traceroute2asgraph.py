import sys
import json
import networkx as nx
import argparse
from matplotlib import pylab as plt
import numpy as np

sys.path.append("../ip2asn/")
import ip2asn
class Traceroute2ASGraph(object):

    """Make AS graph from a raw traceroute data."""

    def __init__(self, fnames, target_asn, ip2asn_db="data/rib.20190301.pickle", 
            ip2asn_ixp="data/ixs_201901.jsonl"):
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
        self.gt = {}
        self.observed_asns = set()

        self.fname_prefix = "graphs/test/"
        # self.fname_prefix = "graphs/test/bad_expert_"


    def find_as_paths(self, fi):
        """Read traceroute file and return AS paths for matching traceroutes"""

        for res in json.load(fi):
            as_path = {"dst": res["dst_addr"], "path": []}
            is_target_asn = self.target_asn is None
            for hop in res["result"]:
                # ignore errors, look only at the first result
                trials = [t for t in hop["result"] if "from" in t]
                if not trials:
                    continue
                trial = trials[0]

                if as_path["path"] and trial["from"] == as_path["path"][-1][0]:
                    continue

                node =  (trial["from"], self.i2a.ip2asn(trial["from"]))
                if node[1]>0:
                    self.observed_asns.add(node[1])
                as_path["path"].append(node)
                if as_path["path"][-1][1] == self.target_asn:
                    is_target_asn = True

            if is_target_asn:
                yield as_path


    def add_path_to_graph(self, path):
        """Add AS path to the graph and label obvious nodes"""

        self.graph.add_path([hop[0] for hop in path["path"]])
        for i, (hop_ip, hop_asn) in enumerate(path["path"][1:-1]):
            if hop_asn > 0 and hop_asn == path["path"][i][1] and hop_asn == path["path"][i+2][1]:
                self.gt[hop_ip] = (hop_asn, 1.0)
            else:
                self.gt[hop_ip] = (hop_asn, .5)
        
        # add the destination IP addr if it responded
        if path["path"][-1][0] == path["dst"] and path["path"][-1][1] > 0:
            self.gt[path["path"][-1][0]] = (path["path"][-1][1], 1.0)

    def save_graphs(self, expert_confidence):

        unique_asns = list(self.observed_asns)
        node_labels = list(self.graph.nodes())

        expert = np.zeros((len(unique_asns), len(node_labels)))
        for ip, (asn, confidence)in self.gt.items():
            idx_ip = node_labels.index(ip)
            idx_asn = unique_asns.index(asn)

            if expert_confidence is None:
                expert[idx_asn, idx_ip] = confidence
            else:
                if confidence >= expert_confidence:
                    expert[idx_asn, idx_ip] = 1.0

        # Save graph to files
        np.savetxt(self.fname_prefix+"ip_graph.txt", nx.to_numpy_array(self.graph), fmt='%s')
        if expert_confidence == 1.0:
            fname = "expert_strict.txt"
        elif expert_confidence == 0.0:
            fname = "expert_loose.txt"
        else:
            fname = "expert_weighted.txt"

        np.savetxt(self.fname_prefix+fname, expert, fmt='%s')
        np.savetxt(self.fname_prefix+"node_labels.txt", node_labels, fmt='%s')
        np.savetxt(self.fname_prefix+"asns_labels.txt", unique_asns, fmt='%s')
        

    def process_files(self):
        """Read all files, make the graph, and save it on disk.
        """

        self.graph = nx.Graph()
        for fname in self.fnames:
            with open(fname, "r") as fi:
                for path in self.find_as_paths(fi):
                    self.add_path_to_graph(path)

        nx.set_node_attributes(self.graph, self.gt, "ASN")
        adj_matrix = nx.to_numpy_array(self.graph)
        node_labels = self.graph.nodes()

        # print(adj_matrix)
        # print(node_labels)
        # print(self.gt)

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
                       nodelist=self.gt.keys(),
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

    args = parser.parse_args()

    ttag = Traceroute2ASGraph(args.traceroutes, args.target_asn)
    ttag.process_files()
    # Save graph to files
    ttag.save_graphs(expert_confidence=0.0)
    ttag.save_graphs(expert_confidence=1.0)
    ttag.save_graphs(expert_confidence=None)


