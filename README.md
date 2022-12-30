# PE_parser
 
### List information of file (c++)
- PointerToEntryPoint
- CheckSum
- ImageBase
- FileAlignment
- SizeOfImage
- Infomation of each section:
    - Name
    - Characteristics
    - RawAddress
    - RawSize
    - VirtualAddress
    - VirtualSize
- Functions the file import and exports 

Command to compile and run
> g++ -o test ./PE_parser/PE_Parser.cpp
 
> test "./fileCheck/notepad32.exe"

Result when run with notepad.exe (64bit)


![](Pasted%20image%2020221226111349.png)
![](Pasted%20image%2020221226111403.png)
![](Pasted%20image%2020221226111420.png)
![](Pasted%20image%2020221226111433.png)

![](Pasted%20image%2020221226111551.png)