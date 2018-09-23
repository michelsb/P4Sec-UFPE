class Node:

    def __init__(self, info):  # constructor of class

        self.info = info  # information for node
        self.left = None  # left leef
        self.right = None  # right leef
        self.level = None  # level none defined

    def __str__(self):
        return str(self.info)  # return as string


class SearchTree:

    def __init__(self):  # constructor of class

        self.root = None

    def create(self, val):  # create binary search tree nodes

        if self.root == None:

            self.root = Node(val)

        else:

            current = self.root

            while 1:

                if val == 0:

                    if current.left:
                        current = current.left
                    else:
                        current.left = Node(val)
                        break;

                elif val == 1:

                    if current.right:
                        current = current.right
                    else:
                        current.right = Node(val)
                        break;

                else:
                    break

    def bft(self):  # Breadth-First Traversal

        self.root.level = 0
        queue = [self.root]
        out = []
        current_level = self.root.level

        while len(queue) > 0:

            current_node = queue.pop(0)

            if current_node.level > current_level:
                current_level += 1
                out.append("\n")

            out.append(str(current_node.info) + " ")

            if current_node.left:
                current_node.left.level = current_level + 1
                queue.append(current_node.left)

            if current_node.right:
                current_node.right.level = current_level + 1
                queue.append(current_node.right)

        print("".join(out))

    def inorder(self, node):

        if node is not None:
            self.inorder(node.left)
            print(node.info)
            self.inorder(node.right)

    def preorder(self, node):

        if node is not None:
            print(node.info)
            self.preorder(node.left)
            self.preorder(node.right)

    def postorder(self, node):

        if node is not None:
            self.postorder(node.left)
            self.postorder(node.right)
            print(node.info)


tree = SearchTree()
arr = [0, 0, 0]
for i in arr:
    tree.create(i)

arr = [0, 1, 0]
for i in arr:
    tree.create(i)

arr = [1, 0, 0]
for i in arr:
    tree.create(i)

arr = [1, 1, 1]
for i in arr:
    tree.create(i)

arr = [0, 1, 1]
for i in arr:
    tree.create(i)

arr = [1, 1, 0]
for i in arr:
    tree.create(i)

arr = [1, 0, 1]
for i in arr:
    tree.create(i)

tree.print_tree(tree.root)
# print('Breadth-First Traversal')
# tree.bft()
# print('Inorder Traversal')
# tree.inorder(tree.root)
# print('Preorder Traversal')
# tree.preorder(tree.root)
# print('Postorder Traversal')
# tree.postorder(tree.root)

