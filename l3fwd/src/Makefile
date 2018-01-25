#   BSD LICENSE
#
#   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
#   Copyright(c) 2017 Hiroki SHIROKURA All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


LIBSLANK := $(HOME)/git/libslankdev
LIBDPDK := $(HOME)/git/libdpdk_cpp
include $(LIBDPDK)/mk/dpdk.cpp.mk

CXXFLAGS += -std=c++11 -I. -O3 -Wall -Werror -Wno-format-security
CXXFLAGS += -I$(LIBSLANK)
CXXFLAGS += $(DPDK_CXXFLAGS) -I$(LIBDPDK)
LDFLAGS  += $(DPDK_LDFLAGS)

.cc.o:
	@echo "CXX $@"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

SRC = main.cc
OBJ = $(SRC:.cc=.o)
TARGET = l3fwd.out

$(TARGET): $(OBJ)
	@echo CXX $@
	@$(CXX) $(CXXFLAGS) $(OBJ) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf *.out *.o

gdb:
	sudo gdb --args ./$(TARGET) \
		--vdev=net_tap0,iface=tap0 \
		--vdev=net_tap1,iface=tap1

run:
	sudo ./$(TARGET) -c 0xf \
		--vdev=net_tap0,iface=tap0 \
		--vdev=net_tap1,iface=tap1

