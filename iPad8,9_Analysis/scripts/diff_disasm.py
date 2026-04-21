import difflib,sys
A='..\\disasm_xprr_21D61.txt'
B='..\\disasm_xprr_21E219.txt'
try:
    a=open(A,'r',encoding='utf-8').read().splitlines()
except Exception as e:
    a=[]
try:
    b=open(B,'r',encoding='utf-8').read().splitlines()
except Exception as e:
    b=[]
if not a and not b:
    print('No disasm files to compare')
    sys.exit(0)
for line in difflib.unified_diff(a,b,fromfile=A,tofile=B,n=3):
    print(line)
