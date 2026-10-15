import collections
from Compiler.exceptions import *

class GraphError(CompilerError):
    pass

class SparseDiGraph(object):
    """ Directed graph suitable when each node only has a small number of edges.

    Edges are stored as a list instead of a dictionary to save memory, leading
    to slower searching for dense graphs.

    Node attributes must be specified in advance, as these are stored in the
    same list as edges.
    """
    def __init__(self, max_nodes, default_attributes=None):
        """ max_nodes: maximum no of nodes
        default_attributes: dict of node attributes and default values """
        if default_attributes is None:
            default_attributes = { 'merges': None }
        self.default_attributes = default_attributes
        self.attribute_pos = dict(list(zip(list(default_attributes.keys()), list(range(len(default_attributes))))))
        self.n = max_nodes
        # attributes of nodes that differ from the default
        self.nodes = {}
        # successors as dictionaries for insertion order
        self.succ = [{} for i in range(self.n)]
        self.pred = [set() for i in range(self.n)]

    def __len__(self):
        return self.n

    def __getitem__(self, i):
        """ Get list of the neighbours of node i """
        return self.succ[i].keys()

    def __iter__(self):
        pass #return iter(self.nodes)

    def __contains__(self, i):
        return i >= 0 and i < self.n

    def add_node(self, i, **attr):
        if i >= self.n:
            raise CompilerError('Cannot add node %d to graph of size %d' % (i, self.n))
        for a,value in list(attr.items()):
            self.set_attr(i, a, value)

    def _get_node(self, i):
        if i not in self.nodes:
            self.nodes[i] = list(self.default_attributes.values())
        return self.nodes[i]

    def set_attr(self, i, attr, value):
        if attr in self.default_attributes:
            self._get_node(i)[self.attribute_pos[attr]] = value
        else:
            raise CompilerError('Invalid attribute %s for graph node' % attr)

    def get_attr(self, i, attr):
        return self._get_node(i)[self.attribute_pos[attr]]

    def remove_node(self, i):
        """ Remove node i and all its edges """
        succ = self[i]
        pred = self.pred[i]
        for v in succ:
            self.pred[v].remove(i)
        for v in pred:
            del self.succ[v][i]
        self.pred[i] = []
        self.nodes.pop(i, None)

    def add_edge(self, i, j):
        succ = self.succ[i]
        if j not in succ:
            self.pred[j].add(i)
            succ[j] = None

    def add_edges_from(self, tuples):
        for edge in tuples:
            self.add_edge(edge[0], edge[1])

    def remove_edge(self, i, j):
        del self.succ[i][j]
        self.pred[j].remove(i)

    def remove_edges_from(self, pairs):
        for i,j in pairs:
            self.remove_edge(i, j)

    def degree(self, i):
        return len(self.succ[i])


def topological_sort(G, nbunch=None, pref=None):
    seen=bytearray(len(G))
    order_explored=[] # provide order and 
    explored=bytearray(len(G)) # fast search
    
    if pref is None:
        succ = G.succ
        def get_children(node):
            return succ[node]
    else:
        def get_children(node):
            if node in pref:
                pref_set = set(pref[node])
                for i in G[node]:
                    if i not in pref_set:
                        yield i
                for i in reversed(pref[node]):
                    yield i
            else:
                for i in G[node]:
                    yield i

    if nbunch is None:
        nbunch = reversed(list(range(len(G))))
    for v in nbunch:     # process all vertices in G
        if explored[v]:
            continue
        fringe=[v]   # nodes yet to look at
        while fringe:
            w=fringe[-1]  # depth first search
            if explored[w]: # already looked down this branch
                fringe.pop()
                continue
            seen[w]=1     # mark as seen
            # Check successors for cycles and for new nodes
            new_nodes=[]
            for n in get_children(w):
                if not explored[n]:
                    if seen[n]: #CYCLE !!
                        raise GraphError("Graph contains a cycle at %d (%s,%s)." % \
                                                        (n, G[n], G.pred[n]))
                    new_nodes.append(n)
            if new_nodes:   # Add new_nodes to fringe
                fringe.extend(new_nodes)
            else:           # No new nodes so w is fully explored
                explored[w]=1
                order_explored.append(w)
                fringe.pop()    # done considering this node
    
    order_explored.reverse() # reverse order explored
    return order_explored
