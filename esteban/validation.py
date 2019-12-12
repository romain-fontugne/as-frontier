import sys
import numpy as np
from collections import Counter

sys.path.append('src/')
import bdrmapit

node_labels_fname = 'esteban/ToSendRomain/20190313T1200_AS2907/node_labels.txt'
asn_labels_fname = 'esteban/ToSendRomain/20190313T1200_AS2907/asns_labels.txt'
esteban_fname = 'esteban/ToSendRomain/Result_StdPageRank_Strict.csv'

asn_labels = [line[:-1] for line in open(asn_labels_fname, 'r').readlines()]
node_labels = [line[:-1] for line in open(node_labels_fname, 'r').readlines()]

matches = Counter()

# Load bdrmapit results
print('Loading bdrmapit results')
bm = bdrmapit.bdrmapit(filter_ips=node_labels)

# Read esteban's results
print('Loading PageRank results')
pr_results = np.recfromcsv(esteban_fname)

print('Comparing Results')
for i, ip in enumerate(node_labels):
    try:
        pr_asn = asn_labels[list(pr_results[i]).index(1)];
    except ValueError:
        pr_asn = None

    bm_asn = bm.ip2asn(ip)

    # Compare results
    if bm_asn is None or pr_asn is None:
       matches.update(['unk']) 
    else:
        matches.update([bm_asn == pr_asn])

print('Number of matches:')
print(matches.most_common())
