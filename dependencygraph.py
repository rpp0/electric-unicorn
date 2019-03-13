import numpy as np
from x86_const_enum import X86ConstEnum
from enum import IntEnum


class DependencyGraphKey(IntEnum):
    KEY = 0
    PLAINTEXT = 1
    COMBINED = 2


class DependencyGraph:
    def __init__(self, default_graph_key: DependencyGraphKey, name=None):
        self._graph = {}
        self._prev_t = {}
        self.name = name
        self.file_name = name.lower().replace(" ", "_") if name is not None else None
        self.default_graph_key = default_graph_key
        self._graph_key = {}

    def __iter__(self):
        return iter(self._graph)

    def __getitem__(self, key):
        return self._graph[key]

    def get_node_id(self, key, t):
        if type(key) is X86ConstEnum:
            identifier = "%s_%d" % (key.name, t)
            readable_name = "%s, t=%d" % (key.name, t)
        else:
            identifier = "%s_%d" % (key, t)
            readable_name = "%s, t=%d" % (hex(key), t)
        return identifier, readable_name

    def node_exists(self, node_id):
        return node_id in self._graph_key

    def update(self, key, b, t, value, is_register=False, skip_dup=True, graph_key=None):
        # If dealing with register, make Enum to avoid confusion with addresses
        if is_register:
            key = X86ConstEnum(key)

        # Add graph identifier for the node (which graph does the node originate from?)
        if graph_key is None:
            graph_key = self.default_graph_key
        node_id, _ = self.get_node_id(key, t)
        self._graph_key[node_id] = graph_key

        # Add node to graph
        if key in self._graph:
            if b in self._graph[key]:
                if skip_dup:
                    prev_t = self._prev_t[key][b]
                    if self._graph[key][b][prev_t] != value:
                        self._graph[key][b][t] = value
                        self._prev_t[key][b] = t
                else:
                    self._graph[key][b][t] = value
            else:
                self._graph[key][b] = {t: value}
                self._prev_t[key][b] = t
        else:
            self._graph[key] = {b: {t: value}}
            self._prev_t[key] = {b: t}

    def get_graph_key(self, node_id):
        return self._graph_key[node_id]

    def _delta_to_str(self, delta_dict):
        result = ""
        for t, v in delta_dict.items():
            if type(v) is str:
                result += "(t=%d,v=%s) " % (t, v)
            else:
                result += "(t=%d,v=%s) " % (t, hex(v))
        return result

    def __repr__(self):
        result = "" if self.name is None else ("%s\n" % self.name)
        for key, deps_dict in sorted(self._graph.items()):
            for bit, deps in deps_dict.items():
                if type(key) is X86ConstEnum:  # Register
                    result += "%s [%d]: %s\n" % (key.name, bit, self._delta_to_str(deps))
                else:
                    result += "0x%08x [%d]: %s\n" % (key, bit, self._delta_to_str(deps))
        return result

    def get_delta_at_t(self, key, t):
        results = []

        for b in self._graph[key]:
            if t in self._graph[key][b]:
                results.append((b, self._graph[key][b][t]))

        return results

    def find_last_t_since(self, key, b, since):
        for t in range(since-1, -1, -1):
            if b in self._graph[key]:
                if t in self._graph[key][b]:
                    return t
        return None

    def find_last_changed_t_since_all(self, ref_key, b, since):
        results = []
        max_last_t = 0
        v = self._graph[ref_key][b][since]

        ref_node_id, _ = self.get_node_id(ref_key, since)
        ref_graph_key = self.get_graph_key(ref_node_id)

        for key in self._graph:
            # Get last state snapshot for a given key and bit since <since>
            last_t = self.find_last_t_since(key, b, since)
            if last_t is None:
                continue

            # Make sure it belongs to the same graph key
            node_id, _ = self.get_node_id(key, last_t)
            graph_key = self.get_graph_key(node_id)
            if ref_graph_key != DependencyGraphKey.COMBINED and graph_key != ref_graph_key:
                continue

            # Get all previous states right before the snapshot
            if last_t > max_last_t:
                results = [(key, b, last_t)]
                max_last_t = last_t
            elif last_t == max_last_t:
                results.append((key, b, last_t))

        return results

    def find_max_t(self):
        max_t = 0
        for key in self._graph:
            for b in self._graph[key]:
                for t in self._graph[key][b]:
                    if t > max_t:
                        max_t = t
        return max_t

    @classmethod
    def from_union(cls, graph1, graph2):
        union_graph = DependencyGraph(DependencyGraphKey.COMBINED, name="Union graph")
        for key in graph1:
            for b in graph1[key]:
                for t in graph1[key][b]:
                    is_register = type(key) is X86ConstEnum
                    union_graph.update(int(key), b, t, graph1[key][b][t], is_register, skip_dup=False, graph_key=graph1.default_graph_key)

        for key in graph2:
            for b in graph2[key]:
                for t in graph2[key][b]:
                    is_register = type(key) is X86ConstEnum
                    node_id, _ = graph2.get_node_id(key, t)
                    if union_graph.node_exists(node_id):
                        union_graph.update(int(key), b, t, 'CB', is_register, skip_dup=False, graph_key=DependencyGraphKey.COMBINED)
                    else:
                        union_graph.update(int(key), b, t, graph2[key][b][t], is_register, skip_dup=False, graph_key=graph2.default_graph_key)

        return union_graph
