def checkNesting(s) : 
 """ 
 checks if brackets, braces and parentheses in expression s 
 are correctly nested 
 argument: s: str 
 returns: boolean: True if nesting is correct, False otherwise 
 outputs error message if incorrect 
 outline written by sands 7/11/10 
 """ 
 myStack = [] 
 i = 0 
 for ch in s : 
    if ch in "{[(" :
        myStack.append(ch)
    elif ch in "}])" : 
        if not myStack:
            print("no matching opening brack for", s[i])
            return False 
        else : 
            top = myStack.pop()
            if top != s[i] :
                print("expected match for top item, got", s[i])
                return False 
    i = i+1 
    if not myStack :
        print("match for top item on stack missing")
        return False 
    else :
        return True 
    
# print(checkNesting("{((3+4)*a[5*(b-c)])/5, 99}"))
print(checkNesting("((3+4)*a[5*(b-c)]"))
