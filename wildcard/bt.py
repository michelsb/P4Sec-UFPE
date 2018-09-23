from binarytree import tree, Node, build

root_zero = Node(2)
root_one = Node(2)

values = [0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1]
count = 0
number_of_values = 0
previous = next_ = None
for index, obj in enumerate(values):
    if count == 0:
        if obj == 0:
            if root_zero.left is None:
                root_zero.left = Node(obj)
            current_node = root_zero.left
        elif obj == 1:
            if root_one.right is None:
                root_one.right = Node(obj)
            current_node = root_one.right
    elif count < 3:
        if obj == 0:
            if current_node.left is None:
                current_node.left = Node(obj)
            current_node = current_node.left
        elif obj == 1:
            if current_node.right is None:
                current_node.right = Node(obj)
            current_node = current_node.right
    count = count + 1
    if count == 3:
        number_of_values = number_of_values + 1
        count = 0


def generate_wildcards_left(levels, levels_nodes, count, wildcard):
    nodes_number = len(levels_nodes[count])
    internal_count = 0
    while internal_count <= nodes_number:
        node = levels_nodes[count][internal_count]
        if node.left and node.right:
            wildcard = wildcard + '*'
        elif node.left is None and node.right is not None:
            wildcard = wildcard + '1'
        elif node.left is not None and node.right is None:
            wildcard = wildcard + '0'
        internal_count = internal_count + 1
        if len(wildcard) == 3:
            print(wildcard)
            wildcard = ''


def generate_wildcards_right(node, count, wildcard):
    if node:
        count = count + 1
        if node.left and node.right:
            wildcard = wildcard + '*'
            generate_wildcards_right(node.left, count, wildcard)
            generate_wildcards_right(node.right, count, wildcard)
        elif node.left is None and node.right is not None:
            wildcard = wildcard + '1'
            generate_wildcards_right(node.right, count, wildcard)
        elif node.left is not None and node.right is None:
            wildcard = wildcard + '0'
            generate_wildcards_right(node.left, count, wildcard)
        if count == 3:
            count = 0
            print(wildcard)
            return wildcard

levels = root_zero.height
print(root_zero)
#print(root_one)
#print(generate_wildcards_left(levels, root_zero.levels, levels, ''))
#print(number_of_values)
#print(generate_wildcards_right(root_one, 0, ''))


#SE O NÓ ANTERIOR POSSUI DOIS FILHOS E ESTES FILHO SÃO FOLHAS, * NOS FILHOS
#SE O NÓ ANTERIOR POSSUIR DOIS FILHOS E ESTES FILHOS SÃO PAIS, VERIFICAR SE TODOS OS FILHOS SÃO PAIS DE DOIS FILHOS, CASO SIM, * NOS FILHOS
#SE NÃO,
