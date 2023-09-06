import string

def create_shift_substitution(n): 
    encoding = {}
    decoding = {}
    alphabet_size = len(string.ascii_uppercase)
    for i in range(alphabet_size):
        letter = string.ascii_uppercase[i]
        subst_letter = string.ascii_uppercase[(i+n)%alphabet_size]

        encoding[letter] = subst_letter
        decoding[subst_letter] = letter
    return encoding, decoding

def encode(message, subst): 
    cipher = ""
    for letter in message: 
        if letter in subst: # if your letter is in the dictionary substitute
            cipher += subst[letter]
        else: # otherwise preserve the letter (important for punctuation and spaces)
            cipher += letter
    return cipher 
    # one liner for the flex that does the same thing 
    # return "".join(subst.get(x, x) for x in messages)

def decode(message, subst): 
    return encode(message, subst)

def printable_substitution(subst):
    # sort by source character so things are alphabetized
    mapping = sorted(subst.items())

    # Then create two lines: source above, target beneath 
    alphabet_line = " ".join(letter for letter, _ in mapping)
    cipher_line = " ".join(subst_letter for _, subst_letter in mapping)
    return "{}\n{}".format(alphabet_line, cipher_line)

if __name__ == "__main__":
    n = 1 
    encoding, decoding = create_shift_substitution(n)
    while True: 
        print("\nShift Encoder Decoder")
        print("-----------------------")
        print("\tCurrent Shift: {}\n".format(n))
        print("\t1. Print Encoding/Decoding Tables.")
        print("\t2. Encode Message.")
        print("\t3. Decode Message.")
        print("\t4. Change Shift.")
        print("\t5. Quit.\n")
        choice = input(">> ")
        print()

        match choice: 
            case '1': 
                print('Encoding Table')
                print(printable_substitution(encoding))
                print('Decoding Table')
                print(printable_substitution(decoding))
            case '2': 
                message = input("\nMessage to encode: ")
                print("Encoded Message: {}".format(encode(message.upper(), encoding)))
            case '3': 
                message = input("\nMessage to decode: ")
                print("Decoded Message: {}".format(decode(message, decoding)))
            case '4': 
                new_shift = input("\nInput new shift (Currently {})".format(n))
                try: 
                    new_shift = int(new_shift)
                    if new_shift < 1: 
                        raise Exception("Shift must be greater than 0")
                    else: 
                        n = new_shift
                        encoding, decoding = create_shift_substitution(n)
                except ValueError:
                    print("Shift {} is not a valid number.".format(new_shift))
            case '5': 
                print("Terminating. This program will self destruct shortly. Happy encrypting!")
                break
            case _: 
                print("Unknown option {}".format(choice))
                    
