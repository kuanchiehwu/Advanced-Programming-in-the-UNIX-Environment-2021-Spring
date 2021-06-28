all: mini

jmp1: mini
	gcc -o jmp1.o -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI test/jmp1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o jmp1 jmp1.o start.o -L. -L.. -lmini
	rm jmp1.o

alarm1: mini
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI test/alarm1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm1 alarm1.o start.o -L. -L.. -lmini
	rm alarm1.o

alarm2: mini
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI test/alarm2.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm2 alarm2.o start.o -L. -L.. -lmini
	rm alarm2.o

alarm3: mini
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI test/alarm3.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm3 alarm3.o start.o -L. -L.. -lmini
	rm alarm3.o

mini:
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC libmini64.asm -o libmini64.o
	gcc -c -g -Wall -fno-stack-protector -fPIC -nostdlib libmini.c
	ld -shared -o libmini.so libmini64.o libmini.o
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC start.asm -o start.o
	
clean:
	rm -f libmini.so libmini64.o libmini.o start.o
	rm -f jmp1 alarm1 alarm2 alarm3