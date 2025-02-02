import bz2


class bdrmapit():
    def __init__(self, 
            node_file='data/bdrmapit/201803/midar-iff.nodes.bz2', 
            node_as_file='data/bdrmapit/201803/midar-iff.nodes.as.bz2', 
            filter_ips=None, load=True):
        """ Initialize object with given data"""

        self.node_file = node_file
        self.node_as_file = node_as_file
        if filter_ips is None:
            self.filter_ips = None
        else:
            self.filter_ips = set(filter_ips)

        self.node2as = {}
        self.ip2node = {}

        if load:
            self.read_node_file()
            self.read_node_as_file()

    def read_node_file(self):
        """Read node file and populate the corresponding dictionary"""

        with bz2.open(self.node_file, 'rt', encoding='utf-8') as fi:
            for line in fi:
                if line.startswith('node'):
                    node_id, _, ips = line[5:-1].partition(':')
                    ips = ips.split(' ')

                    if self.filter_ips is None: 
                        for ip in ips:
                            self.ip2node[ip] = int(node_id[1:])
                    else:
                        inter = self.filter_ips.intersection(ips)
                        for ip in inter:
                            self.ip2node[ip] = int(node_id[1:])

                        # Stop if we got all IPs 
                        self.filter_ips.difference_update(inter)
                        if not self.filter_ips:
                            break

    def read_node_as_file(self):
        """Read node AS file and populate the corresponding dictionary"""

        filter_nodes = set(self.ip2node.values())
        with bz2.open(self.node_as_file, 'rt', encoding='utf-8') as fi:
            for line in fi:
                if line.startswith('node.AS'):
                    _, node_id, asn = line[:-1].split(' ')

                    node = int(node_id[1:])
                    if self.filter_ips is None or node in filter_nodes: 
                        self.node2as[node] = int(asn)

    def ip2asn(self, ip):
        """Map the ip to AS, return None if unknown"""

        bm_asn = None
        if ip in self.ip2node:
            bm_asn = self.node2as.get(self.ip2node[ip], None)

        return bm_asn

