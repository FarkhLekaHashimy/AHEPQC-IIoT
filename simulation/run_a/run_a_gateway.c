/*

 * run_a_gateway.c  -  Run A Gateway (RPL Root)

 *

 * - Starts as RPL root (no border router needed)

 * - Sends periodic discovery beacons so sensors

 *   find the gateway address automatically

 * - Receives full handshake from sensors and ACKs

 *

 * ADD THIS NODE FIRST IN COOJA (node ID = 1)

 */

 

#include "contiki.h"

#include "net/ipv6/simple-udp.h"

#include "net/ipv6/uip-ds6.h"

#include "net/routing/routing.h"

#include "sys/log.h"

#include "random.h"

#include <string.h>

#include <inttypes.h>

 

#include "../project-conf.h"

 

#define LOG_MODULE "A-gw"

#define LOG_LEVEL  LOG_LEVEL_INFO

 

typedef struct {

  uint8_t  session_key[AES256_KEY];

  uint8_t  iv[AES256_IV];

  uint32_t session_id;

} __attribute__((packed)) gw_ack_t;

 

static struct simple_udp_connection data_conn;

static struct simple_udp_connection disc_conn;

static uint32_t sessions = 0;

 

/* Receive handshake from sensor, send ACK */

static void data_rx(struct simple_udp_connection *c,

                    const uip_ipaddr_t *src, uint16_t sport,

                    const uip_ipaddr_t *dst, uint16_t dport,

                    const uint8_t *buf, uint16_t len)

{

  LOG_INFO("Handshake rx %d bytes\n", len);

 

  gw_ack_t ack;

  memset(&ack, 0x02, sizeof(ack));

  ack.session_id = sessions;

 

  simple_udp_sendto(&data_conn, &ack, sizeof(ack), src);

  sessions++;

  LOG_INFO("Session %" PRIu32 " done\n", sessions);

}

 

/* Receive telemetry (ignore content, just count) */

static void disc_rx(struct simple_udp_connection *c,

                    const uip_ipaddr_t *src, uint16_t sport,

                    const uip_ipaddr_t *dst, uint16_t dport,

                    const uint8_t *buf, uint16_t len)

{

  /* Sensors sometimes reply to discovery on this port */

  (void)src; (void)buf; (void)len;

}

 

PROCESS(gw_proc, "RunA Gateway");

AUTOSTART_PROCESSES(&gw_proc);

 

PROCESS_THREAD(gw_proc, ev, data)

{

  static struct etimer et;

  static struct etimer disc_et;

 

  PROCESS_BEGIN();

 

  /* Become RPL root - forms the network */

  NETSTACK_ROUTING.root_start();

  LOG_INFO("RPL root started\n");

 

  /* Register data socket */

  simple_udp_register(&data_conn, UDP_GATEWAY_PORT, NULL,

                      UDP_SENSOR_PORT, data_rx);

 

  /* Register discovery socket */

  simple_udp_register(&disc_conn, UDP_DISCOVER_PORT, NULL,

                      UDP_DISCOVER_PORT, disc_rx);

 

  /* Wait for RPL to initialize */

  etimer_set(&et, 10 * CLOCK_SECOND);

  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

 

  LOG_INFO("Gateway ready - sending discovery beacons\n");

 

  etimer_set(&disc_et, DISCOVER_INTERVAL);

  etimer_set(&et, 30 * CLOCK_SECOND);

 

  while(1) {

    PROCESS_WAIT_EVENT();

 

    if(etimer_expired(&disc_et)) {

      /* Send discovery beacon to all nodes on local link */

      uip_ipaddr_t all_nodes;

      uip_create_linklocal_allnodes_mcast(&all_nodes);

      uint8_t beacon[4] = {0xDE, 0xAD, 0xBE, 0xEF};

      simple_udp_sendto(&disc_conn, beacon, sizeof(beacon), &all_nodes);

      etimer_reset(&disc_et);

    }

 

    if(etimer_expired(&et)) {

      LOG_INFO("Gateway alive sessions=%" PRIu32 "\n", sessions);

      etimer_reset(&et);

    }

  }

 

  PROCESS_END();

}



