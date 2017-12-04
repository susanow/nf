
LIBSLANKDEV := $(HOME)/git/libslankdev
LIBNDPI     := /usr/include/libndpi-1.7.1/libndpi/

CXXFLAGS += -I$(LIBSLANKDEV) -I$(LIBNDPI) -std=c++11
LDFLAGS  += -lpcap -lndpi

all:
	$(CXX) $(CXXFLAGS) main.cc $(LDFLAGS)

