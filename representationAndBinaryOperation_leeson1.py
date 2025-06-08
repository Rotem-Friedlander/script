def decimalToBinary(num:int)->str:
    binary_str=bin(num)[2:]
    binary_str=binary_str.zfill(8)
    return binary_str

def binaryToNegativeBased2(s_bin:str)->str:
    s_neg=""
    if(s_bin[-1]==0):
        s_bin[-1]=1
    for i in s_bin:
        if i=="0":
            s_neg+="1"
        else:
            s_neg+="0"
    if(s_neg[-1]==0):
        s_neg[-1]=1
    return s_neg

bin=decimalToBinary(int(input("Enter a number:"))) #הנחה הקלט תקין
print(bin)
print(binaryToNegativeBased2(bin))