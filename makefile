APP=sfslc

all: $(APP) 

$(APP): $(APP).o    
	gcc -g -o $(APP) $(APP).o -m32 
	
$(APP).o: $(APP).asm
	nasm -f elf32 $(APP).asm -F DWARF

