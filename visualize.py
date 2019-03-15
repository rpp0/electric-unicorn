#!/usr/bin/env python3

import pickle
from dependencygraph import DependencyGraph
from graphviz import Digraph, nohtml
from x86_const_enum import X86ConstEnum
from unicorn.x86_const import *


class DependencyGraphVisualization:
    def __init__(self, graph, lines=True, exclude_partial_registers=True):
        splines = 'line' if lines else 'true'
        self.g = Digraph('g', filename='%s.gv' % graph.file_name, engine='dot', node_attr={'shape': 'record', 'height': '.1'}, graph_attr={'splines': splines})
        self.subgraph = {}
        for t in range(graph.find_max_t()+1):
            self.subgraph[t] = Digraph("subgraph%d" % t, node_attr={'shape': 'record', 'height': '.1'})
            self.subgraph[t].graph_attr.update(rank='same')
        self.nodes = set()
        self.graph = graph
        self.colors = ['red', 'black', 'blue']
        if exclude_partial_registers:
            self.excluded = sorted([  # TODO sometimes only write to _AX happens for example. How to fix?
                UC_X86_REG_EDX,
                UC_X86_REG_DL,
                UC_X86_REG_DH,
                UC_X86_REG_DX,
                UC_X86_REG_EAX,
                UC_X86_REG_AL,
                UC_X86_REG_AH,
                UC_X86_REG_AX,
                UC_X86_REG_EBX,
                UC_X86_REG_BL,
                UC_X86_REG_BH,
                UC_X86_REG_BX,
                UC_X86_REG_ECX,
                UC_X86_REG_CL,
                UC_X86_REG_CH,
                UC_X86_REG_CX,
                UC_X86_REG_EDI,
                UC_X86_REG_DI,
                UC_X86_REG_DIL,
                UC_X86_REG_ESI,
                UC_X86_REG_SI,
                UC_X86_REG_SIL,
                UC_X86_REG_EBP,
                UC_X86_REG_BP,
                UC_X86_REG_BPL,
                UC_X86_REG_R15W,
                UC_X86_REG_R15D,
                UC_X86_REG_R15B,
                UC_X86_REG_R14W,
                UC_X86_REG_R14D,
                UC_X86_REG_R14B,
                UC_X86_REG_R13W,
                UC_X86_REG_R13D,
                UC_X86_REG_R13B,
                UC_X86_REG_R12W,
                UC_X86_REG_R12D,
                UC_X86_REG_R12B,
                UC_X86_REG_R11W,
                UC_X86_REG_R11D,
                UC_X86_REG_R11B,
                UC_X86_REG_R10W,
                UC_X86_REG_R10D,
                UC_X86_REG_R10B,
                UC_X86_REG_R9W,
                UC_X86_REG_R9D,
                UC_X86_REG_R9B,
                UC_X86_REG_R8W,
                UC_X86_REG_R8D,
                UC_X86_REG_R8B,
            ])
        else:
            self.excluded = []
        self.parse()

    def get_field_values_str(self, field_values):
        field_string = ""
        for field_id, field in field_values:
            readable_field = field if type(field) is str else hex(field)
            field_string += "<%d>%s|" % (field_id, readable_field)
        field_string = field_string.rstrip('|')
        return field_string

    def add_state_node(self, key, t):
        # Get id of node
        node_id, readable_name = self.graph.get_node_id(key, t)

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

    def connect_node(self, key, b, t):
        # Don't connect from excluded nodes
        if type(key) is X86ConstEnum and key.value in self.excluded:
            return

        # Add if not yet in graph
        node_id, readable_name = self.graph.get_node_id(key, t)
        if node_id not in self.nodes:
            self.add_state_node(key, t)

        # Connect node to its previous (changed) state
        """
        prev_t = self.graph.find_last_changed_t_since(key, b, t)
        if prev_t is not None:
            prev_node_id, _ = self.graph.get_node_id(key, prev_t)
            self.g.edge("%s:%d" % (prev_node_id, b), "%s:%d" % (node_id, b))
        """
        result = self.graph.find_last_changed_t_since_all(key, b, t)
        for r in result:
            prev_key, prev_b, prev_t = r
            if type(prev_key) is X86ConstEnum and prev_key.value in self.excluded:  # Don't connect to excluded nodes
                continue
            prev_node_id, _ = self.graph.get_node_id(prev_key, prev_t)
            color = self.colors[int(self.graph.get_graph_key(prev_node_id))]
            self.g.edge("%s:%d" % (prev_node_id, prev_b), "%s:%d" % (node_id, b), color=color)

    def parse(self):
        num_keys = len(self.graph._graph.keys())
        for i, key in enumerate(self.graph):
            print("\rParsing %d/%d              " % (i, num_keys), end='')
            for b in self.graph[key]:
                for t in self.graph[key][b]:
                    self.connect_node(key, b, t)

    def show(self):
        for t in self.subgraph:
            self.g.subgraph(self.subgraph[t])
        self.g.view()


if __name__ == "__main__":
    with open('/tmp/key_dependency_graph.p', 'rb') as f:
        key_dependency_graph = pickle.load(f)
    with open('/tmp/plaintext_dependency_graph.p', 'rb') as f:
        plaintext_dependency_graph = pickle.load(f)

    print(key_dependency_graph)
    print(plaintext_dependency_graph)

    union_graph = DependencyGraph.from_union(key_dependency_graph, plaintext_dependency_graph)
    print(union_graph)

    intersection_graph = DependencyGraph.from_intersection(key_dependency_graph, plaintext_dependency_graph)
    print(intersection_graph)

    #d = DependencyGraphVisualization(union_graph, lines=True, exclude_partial_registers=False)
    #d.show()

    #d = DependencyGraphVisualization(intersection_graph, lines=True, exclude_partial_registers=False)
    #d.show()

    d = DependencyGraphVisualization(key_dependency_graph, lines=True, exclude_partial_registers=False)
    d.show()

    #d = DependencyGraphVisualization(plaintext_dependency_graph, lines=True, exclude_partial_registers=False)
    #d.show()

