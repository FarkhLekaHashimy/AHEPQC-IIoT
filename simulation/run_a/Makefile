CONTIKI_PROJECT = run_a_sensor run_a_gateway

all: $(CONTIKI_PROJECT)

# Path from run_a/ back to contiki-ng root
CONTIKI = ../..

TARGET ?= cooja

MODULES += os/net/app-layer/simple-udp

include $(CONTIKI)/Makefile.include
