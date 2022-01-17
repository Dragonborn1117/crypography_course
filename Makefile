TARGET = encrypt
all:
	gcc main.c des.c sha256.c rsa.c aes_ni.c -lgmp -o $(TARGET) -march=native

.Phony:
	clean

clean:
	-del $(TARGET).exe 
