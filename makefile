CC = g++
LIBS = -lpcap
TARGET = packet-stat

$(TARGET): main.cpp
	$(CC) -o $(TARGET) main.cpp $(LIBS)

clean:
	rm -rf $(TARGET)