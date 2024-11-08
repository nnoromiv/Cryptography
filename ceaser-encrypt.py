def encrypt(key, message):
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