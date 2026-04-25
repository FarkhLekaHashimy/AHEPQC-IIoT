CONTIKI_PROJECT = run_b_sensor run_b_gateway

all: $(CONTIKI_PROJECT)

# Path from run_b/ back to contiki-ng root
CONTIKI = ../..

TARGET ?= cooja

MODULES += os/net/app-layer/simple-udp

include $(CONTIKI)/Makefile.include
