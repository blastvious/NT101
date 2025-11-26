# A mono-alphabetic shift cipher attack tool
# looks for most common occurances of letters according to a known
# distribution of letters in the english language.

# Dustin Ray
# TCSS 581 - Spring 2020

def main():
    
    print()
    print("Mono-Alphabetic Substitution Cipher Attack Tool, v 1.0" + "\n")

    # Start by creating a list of known distributions of letters in the english language.
    # List taken from INTRODUCTION TO MODERN CRYPTOGRAPHY, Second Edition 
    # International Standard Book Number-13: 978-1-4665-7027-6

    letterDistribution = {
        "e": 12.7,
        "t": 9.1,
        "a": 8.2,
        "i": 7.0,
        "n": 6.7,
        "s": 6.3,
        "h": 6.1,
        "r": 6.0,
        "d": 4.3,
        "l": 4.0,
        "u": 2.8,
        "c": 2.8,
        "w": 2.4,
        "m": 2.4, 
        "f": 2.2,
        "g": 2.0,
        "y": 2.0,
        "p": 1.9,
        "b": 1.5,
        "o": 1.5,
        "v": 1.0,
        "k": 0.8,
        "j": 0.2,
        "x": 0.2,
        "q": 0.1,
        "z": 0.1
        }


    
    #sort the above dictionary by value in ascending order
    print("Standard distribution of letters in any given english message: " )
    for w in sorted(letterDistribution, key=letterDistribution.get, reverse=True):
        print(w + " appears: ", str(letterDistribution[w]) + "% of the time")



    # given ciphertext message to attempt to decrypt.
    message = ('JGRMQOYGHMVBJWRWQFPWHGFFDQGFPFZRKBEEBJIZQQOCIBZKLFAFGQVF'
    'ZFWWEOGWOPFGFHWOLPHLRLOLFDMFGQWBLWBWQOLKFWBYLBLYLFSFLJGRMQBOLWJVFPF'
    'WQVHQWFFPQOQVFPQOCFPOGFWFJIGFQVHLHLROQVFGWJVFPFOLFHGQVQVFILEOGQILHQ'
    'FQGIQVVOSFAFGBWQVHQWIJVWJVFPFWHGFIWIHZZRQGBABHZQOCGFHX')
    
    # create an unordered set out of chars in message
    s = set(message)
    
    #sum up total number of characters counted
    sum = 0;

    #try and sort the set
    sorted(s)
    
    print("\n")
    print("Distribution of letters in given message: " )

    # construct a dictionary made of letters in the message as keys
    # and frequency at which they occur as values
    d = {}
    for ch in s:
        if ch in message:
            sum += message.count(ch)
            d[ch] = round(((message.count(ch) / len(message)) * 100), 2)

    #sort the dictionary by value instead of key
    for w in sorted(d, key=d.get, reverse=True):
        print(w + " appears: ", str(d[w]) + "% of the time")

    print()
    #print length of message
    print("length of message: " + str(len(message)))
    #print total characters counted, make sure they match with
    #message length
    print("Total number of characters counted: " + str(sum))

    print("\n")
    print("Based on the standard character distribution, it is possible that: " + "\n")

    dS = sorted(d, key=d.get, reverse=True)
    stdS = sorted(letterDistribution, key=letterDistribution.get, reverse=True)

    k1 = letterDistribution.keys()

    #print(k1)

    for i in range(len(dS)):
        print(dS[i] + " = " + stdS[i])

    print("\n" + "(letters not found in the ciphertext are not listed here)" + "\n")


main()