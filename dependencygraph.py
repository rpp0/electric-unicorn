import numpy as np
from x86_const_enum import X86ConstEnum


class DependencyGraph:
    def __init__(self, name=None):
        self._graph = {}
        self._prev_t = {}
        self.name = name

    def __iter__(self):
        return iter(self._graph)

    def __getitem__(self, key):
        return self._graph[key]

    def update(self, key, b, t, value, is_register=False, skip_dup=True):
        if is_register:
            key = X86ConstEnum(key)

        if key in self._graph:
            if b in self._graph[key]:
                if skip_dup:
                    prev_t = self._prev_t[key][b]
                    if prev_t is not None and self._graph[key][b][prev_t] != value:
                        self._graph[key][b][t] = value
                        self._prev_t[key][b] = t
                else:
                    self._graph[key][b][t] = value
            else:
                self._graph[key][b] = {t: value}
                self._prev_t[key][b] = None
        else:
            self._graph[key] = {b: {t: value}}
            self._prev_t[key] = {b: None}

    def _delta_to_str(self, delta_dict):
        result = ""
        for t, v in delta_dict.items():
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

        for key in self._graph:
            # Get last state snapshot for a given key and bit since <since>
            last_t = self.find_last_t_since(key, b, since)
            if last_t is None:
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
