class DisjointSet:
    def __init__(self):
        self.disjoint_set = []

    def put(self, index: int, parent_index: int):
        if index >= len(self.disjoint_set):
            self.disjoint_set.extend([-1] *
                                     (index + 1 - len(self.disjoint_set)))
        self.disjoint_set[index] = parent_index

    def _get(self, index: int, start_index: int) -> int:
        # use start_index avoid loop

        # [-1, index, start_index] maybe root index for each tree
        if self.disjoint_set[index] in [-1, index, start_index]:
            if self.disjoint_set[index] > 0:
                return self.disjoint_set[index]
            else:
                return index

        # find root index to do full compress
        root_index = self._get(self.disjoint_set[index], start_index)
        self.disjoint_set[index] = root_index
        return root_index

    def get(self, index: int) -> int:
        start_index = index
        path = []
        while self.disjoint_set[index] not in [-1, index, start_index]:
            path.append(index)
            index = self.disjoint_set[index]
        parent = self.disjoint_set[index]
        root = parent if parent > 0 else index
        for child in path:
            self.disjoint_set[child] = root
        return root
