def encrypt(key, message):
    """
    The `encrypt` function takes a key and a message as input, converts the message to uppercase, shifts
    each letter in the message by the key value in the alphabet, and returns the encrypted message.
    
    :param key: The `key` parameter in the `encrypt` function is an integer value that represents the
    shift value used for encrypting the message. It determines how many positions each letter in the
    message should be shifted in the alphabet to create the encrypted message
    :param message: The `message` parameter is the text that you want to encrypt using the Caesar cipher
    algorithm
    :return: The `encrypt` function is returning the encrypted message after shifting each letter in the
    input message by the specified key value. The encrypted message is in uppercase.
    """
    message = message.upper()
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = ""
    
    for letter in message:
        if letter in alpha:
            num = alpha.find(letter)
            new_num = (num + key) % len(alpha)
            result += alpha[new_num]
        else:
            result += letter
    return result

def main() -> None:
    try:
        message = input("Enter message: ")
        key = int(input("Enter key: "))
        
        encrypted = encrypt(key, message)
        file_name = f"encrypted_{key}.txt"
        encrypted_file = open(file_name, "w")
        encrypted_file.write(encrypted)
        
    except KeyboardInterrupt:
        print("Program terminated")
    except ValueError:
        print("Key must be an integer")
    except FileNotFoundError:
        print("File not found")
    except Exception as e:
        print("Error: ", e) 
    finally:
        encrypted_file.close()
        print("End of program")
    
    return None

if __name__ == "__main__":
    main()