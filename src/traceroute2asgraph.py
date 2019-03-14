import sys
import json
import networkx as nx
import argparse

sys.path.append("../ip2asn/")
import ip2asn
class Traceroute2ASGraph(object):

    """Make AS graph from a raw traceroute data."""

    def __init__(self, fnames, target_asn, ip2asn_db="data/rib.20190301.pickle", 
            ip2asn_ixp="data/ixs_201901.jsonl"):
        """fnames: traceroutes filenames
        target_asn: keep only traceroutes crossing this ASN, None to get all 
                    traceroutes"""
    
        self.fnames = fnames
        self.target_asn = target_asn
        self.i2a = ip2asn.ip2asn(ip2asn_db, ip2asn_ixp)
        self.graph = None
        self.gt = {}


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
                as_path["path"].append(node)
                if as_path["path"][-1][1] == self.target_asn:
                    is_target_asn = True

            if is_target_asn:
                print(as_path)
                yield as_path


    def add_path_to_graph(self, path):
        """Add AS path to the graph and label obvious nodes"""

        self.graph.add_path([hop[0] for hop in path["path"]])
        for i, (hop_ip, hop_asn) in enumerate(path["path"][1:-1]):
            if hop_asn > 0 and hop_asn == path["path"][i][1] and hop_asn == path["path"][i+2][1]:
                self.gt[hop_ip] = hop_asn
        
        # add the destination IP addr if it responded
        if path["path"][-1][0] == path["dst"] and path["path"][-1][1] > 0:
            self.gt[path["path"][-1][0]] = path["path"][-1][1]


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

        print(adj_matrix)
        print(node_labels)
        print(self.gt)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Make AS graph from raw traceroute data')
    parser.add_argument('--target-asn', 
                    help='keep only traceroute crossing this ASN')
    parser.add_argument('traceroutes', nargs='+',
                    help='traceroutes files (json format)')

    args = parser.parse_args()

    ttag = Traceroute2ASGraph(args.traceroutes, args.target_asn)
    ttag.process_files()
