TARGET = uprobe ufunc


.PHONY: clean

all: uprobe ufunc
	make -C kmod

clean:
	rm -rf *.o
	rm -rf $(TARGET)
	make -C kmod clean

$(TARGET) : % : %.o
	$(CC) -o $@ $< -lelf

%.o : %.c
	$(CC) -c -g $<
