import math
from utils.wildcards import generate_patterns, permutation_pattern

def convert_array_string_to_int(array):
    binaryArray = [int(element) for element in array]
    return binaryArray

def wild_card_search(binaryWild, hashElement, maxWild, solution):

    provisorySolution = permutation_pattern(binaryWild,maxWild)

    setHashElement = set(hashElement)
    hashPotentialSolution = {}

    for arr in provisorySolution:
        hashPotentialSolution[arr] = generate_patterns(arr)

    has_validSolution = False
    for key in hashPotentialSolution.keys():
        setListBinaries = set(hashPotentialSolution.get(key))
        if len(setListBinaries-setHashElement) == 0:
            solution.append(key)
            has_validSolution = True

    for key in solution:
        if key in hashPotentialSolution:
            listBinaries = hashPotentialSolution.get(key)
            for element in listBinaries:
                key2 = element
                if key2 in hashElement:
                    del hashElement[key2]

    return has_validSolution

def generate_values_with_wildcards(bin_list, size):

    numberOfBits = size
    solution = []
    maxWildCard = 10000

    hashBinaryElement = {}
    for value in bin_list:
        hashBinaryElement[value] = convert_array_string_to_int(value)

    while len(hashBinaryElement) > 0:

        arraySum0 = [0 for i in range(0,numberOfBits)]
        arraySum1 = [0 for i in range(0,numberOfBits)]

        for key in hashBinaryElement.keys():
            binaryArray = hashBinaryElement.get(key)
            for index in range(0,len(binaryArray)):
                if binaryArray[index] == 0:
                    arraySum0[index]+=1
                else:
                    arraySum1[index]+=1

        listSize = len(hashBinaryElement)
        amountOfWildcard = int(math.log(listSize,2))

        if amountOfWildcard < maxWildCard:
            maxWildCard = amountOfWildcard

        requiredEntries = int(math.pow(2,maxWildCard)/2)
        wildCardTest = [2 for i in range(0,numberOfBits)]

        for index in range(0,numberOfBits):
            if arraySum0[index] == 0:
                wildCardTest[index] = 1
            elif arraySum1[index] == 0:
                wildCardTest[index] = 0
            elif (arraySum1[index] > requiredEntries) and (arraySum0[index] < requiredEntries):
                wildCardTest[index] = 1
            elif (arraySum0[index] > requiredEntries) and (arraySum1[index] < requiredEntries):
                wildCardTest[index] = 0

        vSolution = False

        while True:
            vSolution = wild_card_search(wildCardTest, hashBinaryElement, maxWildCard, solution)
            maxWildCard-=1
            if (vSolution) or (maxWildCard <= 0):
                break

    return [s.replace("2", "*") for s in solution]

