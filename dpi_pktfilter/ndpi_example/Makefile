
LIBSLANKDEV := $(HOME)/git/libslankdev
CXXFLAGS += -I$(LIBSLANKDEV) -std=c++11 -I/usr/include/libndpi-1.7.1/libndpi -g -O0
LDFLAGS  += -lndpi -lpcap

all:
	$(CXX) $(CXXFLAGS) main.cc $(LDFLAGS)

clean:
	rm -f *.out

run:
	./a.out http_flow.pcap

