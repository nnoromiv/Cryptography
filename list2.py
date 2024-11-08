myList = [1,2,3,4,5,6,7,8,9,10] 

# print the list using print 
print(myList) 

# myList[7] = 77
myList.append(23)

del myList[2]
del myList[5]

for e in myList:
    print (e)

print("The last two items in the list are", myList[-2], "and", myList[-1])
 
# examine some slices 
print("myList[:4] is ", myList[:4]) 
print("myList[0:5] is ", myList[0:5]) 
print("myList[5:8] is ", myList[5:8]) 
print("myList[8:] is ", myList[8:])