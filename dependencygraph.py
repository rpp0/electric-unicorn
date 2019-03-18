from collections import namedtuple
from x86_const_enum import X86ConstEnum
from enum import IntEnum

ByTEntry = namedtuple("ByTEntry", ["key", "bit", "value"])


class DependencyGraphKey(IntEnum):
    KEY = 0
    PLAINTEXT = 1
    COMBINED = 2


class DependencyGraph:
    def __init__(self, default_graph_key: DependencyGraphKey, name=None):
        self._graph = {}
        self._prev_t = {}
        self._last_t = {}
        self._by_t = {}
        self.name = name
        self.file_name = name.lower().replace(" ", "_") if name is not None else None
        self.default_graph_key = default_graph_key
        self._graph_key = {}

    def __iter__(self):
        return iter(self._graph)

    def __getitem__(self, key):
        return self._graph[key]

    def has_same_deps(self, other):
        for key in self._graph:
            if key not in other:
                return False
            for b in self._graph[key]:
                if b not in other[key]:
                    return False
                for t in self._graph[key][b]:
                    if t not in other[key][b]:
                        return False

        for key in other:
            if key not in self._graph:
                return False
            for b in other[key]:
                if b not in self._graph[key]:
                    return False
                for t in other[key][b]:
                    if t not in self._graph[key][b]:
                        return False

        return True

    def get_node_id(self, key, t):
        if type(key) is X86ConstEnum:
            identifier = "%s_%d" % (key.name, t)
            readable_name = "%s, t=%d" % (key.name, t)
        else:
            identifier = "%s_%d" % (key, t)
            readable_name = "%s, t=%d" % (hex(key), t)
        return identifier, readable_name

    def node_exists(self, key, b, t):
        if key in self._graph:
            if b in self._graph[key]:
                if t in self._graph[key][b]:
                    return True
        return False

    def update_prev(self, key, b, t):
        last_t = self._last_t[key][b]
        if key in self._prev_t:
            if b in self._prev_t[key]:
                self._prev_t[key][b][t] = last_t
            else:
                self._prev_t[key][b] = {t: last_t}
        else:
            self._prev_t[key] = {b: {t: last_t}}

    def update(self, key, b, t, value, is_register=False, skip_dup=True, graph_key=None):
        # If dealing with register, make Enum to avoid confusion with addresses
        if is_register:
            key = X86ConstEnum(key)

        # Add graph identifier for the node (which graph does the node originate from?)
        if graph_key is None:
            graph_key = self.default_graph_key
        node_id, _ = self.get_node_id(key, t)
        self._graph_key[node_id] = graph_key

        # Add node to graph by time
        entry = ByTEntry(key=key, bit=b, value=value)
        if t in self._by_t:
            self._by_t[t].append(entry)
        else:
            self._by_t[t] = [entry]

        # Add node to graph by key
        if key in self._graph:
            if b in self._graph[key]:
                last_t = self._last_t[key][b]

                if skip_dup:
                    if self._graph[key][b][last_t] != value:
                        self._graph[key][b][t] = value
                        self.update_prev(key, b, t)
                        self._last_t[key][b] = t
                else:
                    self._graph[key][b][t] = value
                    self.update_prev(key, b, t)
                    self._last_t[key][b] = t
            else:
                self._graph[key][b] = {t: value}
                self._last_t[key][b] = t
        else:
            self._graph[key] = {b: {t: value}}
            self._last_t[key] = {b: t}

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

    def find_last_changed_t_since_all(self, ref_key, b, since):
        results = []
        max_last_t = 0

        ref_node_id, _ = self.get_node_id(ref_key, since)
        ref_graph_key = self.get_graph_key(ref_node_id)

        for key in self._graph:
            # Get last state snapshot for a given key and bit since <since>
            try:
                last_t = self._last_t[key][b]
                if last_t >= since:
                    continue
            except KeyError:
                continue  # No previous entry

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
                    if union_graph.node_exists(key, b, t):
                        combvalue = "%s, %s" % (hex(graph1[key][b][t]), hex(graph2[key][b][t]))
                        union_graph.update(int(key), b, t, combvalue, is_register, skip_dup=False, graph_key=DependencyGraphKey.COMBINED)
                    else:
                        union_graph.update(int(key), b, t, graph2[key][b][t], is_register, skip_dup=False, graph_key=graph2.default_graph_key)

        return union_graph

    @classmethod
    def from_intersection(cls, graph1, graph2):
        intersection_graph = DependencyGraph(DependencyGraphKey.COMBINED, name="Intersection graph")
        for key in graph1:
            for b in graph1[key]:
                for t in graph1[key][b]:
                    is_register = type(key) is X86ConstEnum
                    if graph2.node_exists(key, b, t):
                        combvalue = "%s, %s" % (hex(graph1[key][b][t]), hex(graph2[key][b][t]))
                        intersection_graph.update(int(key), b, t, combvalue, is_register, skip_dup=False, graph_key=DependencyGraphKey.COMBINED)

        return intersection_graph
