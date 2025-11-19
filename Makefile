CC = gcc
CFLAGS = -std=c99 -Wall -O0 -g -municode -mwindows
LIBS = -lws2_32 -lshell32 -lshlwapi -lcomctl32 -lgdi32 -ladvapi32 -luxtheme -ldwmapi -lsodium -lzip -lsqlite3 -lcomctl32
TARGET = MyPasswordVault.exe
SRC = main.c core.c mdlinkedlist.c modern_ui.c resources.o

all:
	windres resources.rc -O coff -o resources.o
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET) *.o
