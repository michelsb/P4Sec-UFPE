import datetime
import itertools

def diff_bin(a, b):
    diff = list()
    for i in range(len(a)):
        if a[i] != b[i]:
            diff.append(i)
    return diff

def convert_ip_to_bin(ip):
    octets = map(int, ip.split('/')[0].split('.'))  # '1.2.3.4'=>[1, 2, 3, 4]
    binary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*octets)
    range = int(ip.split('/')[1]) if '/' in ip else None
    return binary[:range] if range else binary

def convert_bin_to_ip(bin):
    first_octet = int(bin[0:8], 2)
    second_octet = int(bin[8:16], 2)
    third_octet = int(bin[16:24], 2)
    fourth_octet = int(bin[24:32], 2)

    return "%d.%d.%d.%d" % (first_octet, second_octet, third_octet, fourth_octet)

def generate_pattern_ports(pattern):
    a = [['0', '1'] if (c == '*') else c for c in pattern]
    b = [''.join(lst) for lst in list(itertools.product(*a))]
    return [int(i, 2) for i in b]

def generate_pattern_ips(pattern):
    a = [['0', '1'] if (c == '*') else c for c in pattern]
    b = [''.join(lst) for lst in list(itertools.product(*a))]
    return [convert_bin_to_ip(i) for i in b]

def count_pattern_elements(pattern):
    a = [['0', '1'] if (c == '*') else c for c in pattern]
    b = [''.join(lst) for lst in list(itertools.product(*a))]
    return len(b)


def results_evaluation(min_num, max_num, results):
    count = 0
    for pattern in results:
        count += count_pattern_elements(pattern)
    print("Number of ports: " + str(max_num - min_num + 1))
    print("Number of patterns: " + str(len(results)))
    print("Number of ports in patterns: " + str(count))

def generate_patterns(bin_list):
    remained_values = []
    current_column = bin_list

    while True:

        new_column = []

        while True:
            base = current_column[0]

            index = 1

            while index < len(current_column):
                next_value = current_column[index]
                diff = diff_bin(base, next_value)
                if len(diff) == 1:
                    del current_column[index]
                    del current_column[0]
                    index = diff[0]
                    new_value = base[:index] + "*" + base[index + 1:]
                    new_column.append(new_value)
                    break
                index += 1
            else:
                remained_values.append(base)
                del current_column[0]

            if len(current_column) == 1:
                remained_values.append(current_column[0])
                break

            if len(current_column) == 0:
                break

        if len(new_column) > 0:
            current_column = new_column
        else:
            break

    return remained_values

def convert_to_wildcards(df, field, type_field, list_groups=None):
    bin_list = []

    if (list_groups is None) or (len(list_groups) == 0):
        df_filtered = df[field]
    else:
        filter = df[list_groups[0][0]] == list_groups[0][1]
        for group in list_groups[1:]:
            filter = filter & (df[group[0]] == group[1])
        df_filtered = df[filter][field]

    list_values = df_filtered.drop_duplicates().sort_values(ascending=True).tolist()

    if type_field == "ip":
        for value in list_values:
            bin_list.append(convert_ip_to_bin(value))
    elif type_field == "port":
        for value in list_values:
            bin_list.append('{:016b}'.format(value))

    wildcards = generate_patterns(bin_list)

    if type_field == "ip":
        for pattern in wildcards:
            elements = generate_pattern_ips(pattern)
            #df_filtered = df_filtered.replace(elements, pattern)
            df_filtered = df_filtered.apply(lambda x: pattern if x in elements else x)
    elif type_field == "port":
        for pattern in wildcards:
            elements = generate_pattern_ports(pattern)
            #df_filtered = df_filtered.replace(elements, pattern)
            df_filtered = df_filtered.apply(lambda x: pattern if x in elements else x)

    df.update(df_filtered)

    return wildcards

def generate_flows_with_wildcards(df):
    print("# " + str(datetime.datetime.now()) + " - Generating Flows with Wildcards...")
    groupsSrcIP = convert_to_wildcards(df, "srcIP", "ip")

    for groupSrcIP in groupsSrcIP:
        #print("> Group Source IP: " + groupSrcIP)
        groupsDstIP = convert_to_wildcards(df, "dstIP", "ip", [("srcIP", groupSrcIP)])
        for groupDstIP in groupsDstIP:
            #print(">> Group Destination IP: " + groupDstIP)
            groupsSrcPort = convert_to_wildcards(df, "srcPort", "port", [("srcIP", groupSrcIP), ("dstIP", groupDstIP)])
            for groupSrcPort in groupsSrcPort:
                #print(">> Group Source Port: " + groupSrcPort)
                groupsDstPort = convert_to_wildcards(df, "dstPort", "port", [("srcIP", groupSrcIP), ("dstIP", groupDstIP),
                                                                             ("srcPort", groupSrcPort)])
                #print(">>> Groups Destination Port: " + str(groupsDstPort))
    print("# " + str(datetime.datetime.now()) + " - Flows Generated...")

def convert_bin_to_value_mask(bin_value):
    value = bin_value.replace('*','0')
    mask = bin_value.replace('0','1').replace('*','0')
    return bin(int(value,2)),bin(int(mask,2))