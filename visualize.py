#!/usr/bin/env python3

import pickle
from dependencygraph import DependencyGraph
from graphviz import Digraph, nohtml
from x86_const_enum import X86ConstEnum
from unicorn.x86_const import *


class DependencyGraphVisualization:
    def __init__(self, graph):
        self.g = Digraph('g', filename='tree.gv', engine='dot', node_attr={'shape': 'record', 'height': '.1'}, graph_attr={'splines': 'line'})
        self.subgraph = {}
        for t in range(graph.find_max_t()+1):
            self.subgraph[t] = Digraph("subgraph%d" % t, node_attr={'shape': 'record', 'height': '.1'})
            self.subgraph[t].graph_attr.update(rank='same')
        self.nodes = set()
        self.graph = graph
        self.excluded = [
            UC_X86_REG_EDX,
            UC_X86_REG_DL,
            UC_X86_REG_DH,
            UC_X86_REG_DX,
            UC_X86_REG_EAX,
            UC_X86_REG_AL,
            UC_X86_REG_AH,
            UC_X86_REG_AX,
        ]
        self.parse()

    def get_field_values_str(self, field_values):
        field_string = ""
        for field_id, field in field_values:
            readable_field = hex(field)
            field_string += "<%d>%s|" % (field_id, readable_field)
        field_string = field_string.rstrip('|')
        return field_string

    def add_state_node(self, key, t):
        # Get id of node
        node_id, readable_name = self.get_node_id(key, t)

        # Get all fields (values of b) for the node
        field_initial_values = self.graph.get_delta_at_t(key, t)  # Make the node contain all fields (b) already
        fields_values_str = self.get_field_values_str(field_initial_values)

        # Create the node in the graph visualization
        #half = (0x004a0b00 - 0x004a0a00) / 2
        #xpos = 0 if type(key) is X86ConstEnum else (key - 0x004a0a00 - half)
        xpos = 0
        self.subgraph[t].node(node_id, nohtml("<name>%s|%s" % (readable_name, fields_values_str)), pos="%d,%d!" % (xpos, -t*8))
        #self.subgraph[t].node(node_id, nohtml("<name>%s|%s" % (readable_name, fields_values_str)))
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
        # Don't connect from excluded nodes
        if type(key) is X86ConstEnum and key.value in self.excluded:
            return

        # Add if not yet in graph
        node_id, readable_name = self.get_node_id(key, t)
        if node_id not in self.nodes:
            self.add_state_node(key, t)

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
            if type(prev_key) is X86ConstEnum and prev_key.value in self.excluded:  # Don't connect to excluded nodes
                continue
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
