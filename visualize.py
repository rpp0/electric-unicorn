#!/usr/bin/env python3

import pickle
from dependencygraph import DependencyGraph
from graphviz import Digraph, nohtml
from x86_const_enum import X86ConstEnum


class DependencyGraphVisualization:
    def __init__(self, graph):
        self.g = Digraph('g', filename='tree.gv', node_attr={'shape': 'record', 'height': '.1'})
        self.subgraph = {}
        for t in range(graph.find_max_t()+1):
            self.subgraph[t] = Digraph("subgraph%d" % t, node_attr={'shape': 'record', 'height': '.1'})
            self.subgraph[t].graph_attr.update(rank='same')
        self.nodes = set()
        self.graph = graph
        self.parse()

    def get_field_values_str(self, field_values):
        field_string = ""
        for field_id, field in field_values:
            readable_field = hex(field)
            field_string += "<%d>%s|" % (field_id, readable_field)
        field_string = field_string.rstrip('|')
        return field_string

    def add_state_node(self, node_id, field_initial_values, level=0, readable_name=""):
        fields_values_str = self.get_field_values_str(field_initial_values)
        #self.g.node(node_id, nohtml("<name>%s|%s" % (readable_name, fields_values_str)))
        self.subgraph[level].node(node_id, nohtml("<name>%s|%s" % (readable_name, fields_values_str)))
        self.nodes.add(node_id)
        # print("Added node %s:%s" % (node_id, fields_values_str))

    def get_node_id(self, key, t):
        if type(key) is X86ConstEnum:
            identifier = "%s_%d" % (key.name, t)
            readable_name = "%s, t=%d" % (key.name, t)
        else:
            identifier = "%s_%d" % (key, t)
            readable_name = "%s, t=%d" % (hex(key), t)
        return identifier, readable_name

    def connect_node(self, key, b, t):
        # Add if not yet in graph
        node_id, readable_name = self.get_node_id(key, t)
        if node_id not in self.nodes:
            field_values = self.graph.get_delta_at_t(key, t)  # Make the node contain all fields (b) already
            self.add_state_node(node_id, field_values, level=t, readable_name=readable_name)

        # Connect node to its previous (changed) state
        """
        prev_t = self.graph.find_last_changed_t_since(key, b, t)
        if prev_t is not None:
            prev_node_id, _ = self.get_node_id(key, prev_t)
            self.g.edge("%s:%d" % (prev_node_id, b), "%s:%d" % (node_id, b))
        """
        result = self.graph.find_last_changed_t_since_all(key, b, t)
        for r in result:
            prev_key, prev_b, prev_t = r
            prev_node_id, _ = self.get_node_id(prev_key, prev_t)
            self.g.edge("%s:%d" % (prev_node_id, prev_b), "%s:%d" % (node_id, b))

    def parse(self):
        for key in self.graph:
            for b in self.graph[key]:
                for t in self.graph[key][b]:
                    self.connect_node(key, b, t)

    def show(self):
        for t in self.subgraph:
            self.g.subgraph(self.subgraph[t])
        self.g.view()


if __name__ == "__main__":
    with open('/tmp/dependency_graph.p', 'rb') as f:
        dependency_graph = pickle.load(f)
    print(dependency_graph)

    d = DependencyGraphVisualization(dependency_graph)
    d.show()

    #g.node('node0', nohtml('<f0> |<f1> G|<f2>'))
    #g.edge('node0:f2', 'node4:f1')
