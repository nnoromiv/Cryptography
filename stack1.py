myStack = [] 

running = True

while running : 
 print("\nStack contents:", myStack, "\n") # generate extra blank lines in output 
 line = input("Select an option: push, pop or quit: ") 
 if line=="quit": 
    running = False
 elif line=="pop" :
    stackLen = len(myStack)
    
    if stackLen == 0:
        print("Stack is Empty")
    else:
        print("Popped", myStack.pop()) 
    
 elif line=="push" : 
    myString = input("Enter name to push onto stack: ") 
    myStack.append(myString) 
else : 
 print("Invalid selection") 
