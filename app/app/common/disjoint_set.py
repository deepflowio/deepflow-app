class DisjointSet:
    def __init__(self):
        self.disjoint_set = []

    def put(self, index: int, parent_index: int):
        if index >= len(self.disjoint_set):
            self.disjoint_set.extend([None] *
                                     (index + 1 - len(self.disjoint_set)))
        self.disjoint_set[index] = parent_index

    def get(self, index: int) -> int:
        if self.disjoint_set[index] == -1:
            return index
        root_index = self.get(self.disjoint_set[index])
        self.disjoint_set[index] = root_index
        return root_index
