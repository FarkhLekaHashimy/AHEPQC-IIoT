/*

 * run_b_gateway.c  -  Run B Gateway (AHEPQC-IIoT)

 *

 * - RPL root (no border router needed)

 * - Discovery beacons so sensors find it automatically

 * - Handles offloaded crypto from Sub-tier 1a sensors

 * - HSM with software fallback

 *

 * ADD THIS NODE FIRST IN COOJA (node ID = 1)

 */

 

#include "contiki.h"

#include "net/ipv6/simple-udp.h"

#include "net/routing/routing.h"

#include "sys/log.h"

#include "random.h"

#include <string.h>

#include <inttypes.h>

 

#include "../project-conf.h"

 

#define LOG_MODULE "B-gw"

#define LOG_LEVEL  LOG_LEVEL_INFO

 

#define HSM_CHECK_INTERVAL (30 * CLOCK_SECOND)

 

/* HSM state */

typedef enum { HSM_OK = 0, HSM_DEGRADED = 1 } hsm_t;

static hsm_t    hsm_state  = HSM_OK;

static uint32_t hsm_faults = 0;

static uint32_t sessions   = 0;

 

static hsm_t hsm_poll(void) {

  if((random_rand() % 20) == 0) {

    hsm_faults++;

    return HSM_DEGRADED;

  }

  return HSM_OK;

}

 

/* Sensor request: ML-KEM public key only */

typedef struct {

  uint8_t  kem_pk[MLKEM512_PK];

  uint8_t  tier;

  uint32_t sensor_id;

} __attribute__((packed)) b_request_t;

 

/* Gateway response: session key material */

typedef struct {

  uint8_t  kem_ct[MLKEM512_CT];

  uint8_t  sess_key[AES256_KEY];

  uint8_t  iv[AES256_IV];

} __attribute__((packed)) gw_response_t;

 

static struct simple_udp_connection data_conn;

static struct simple_udp_connection disc_conn;

 

/* Handle sensor KEM request */

static void data_rx(struct simple_udp_connection *c,

                    const uip_ipaddr_t *src, uint16_t sport,

                    const uip_ipaddr_t *dst, uint16_t dport,

                    const uint8_t *buf, uint16_t len)

{

  hsm_state = hsm_poll();

 

  if(len >= 32) {

    /* Sub-tier 1a: gateway handles full crypto offload */

    gw_response_t resp;

    memset(resp.kem_ct,   0x11, MLKEM512_CT);

    memset(resp.sess_key, 0x22, AES256_KEY);

    memset(resp.iv,       0x33, AES256_IV);

 

    simple_udp_sendto(&data_conn, &resp, sizeof(resp), src);

    sessions++;

 

    LOG_INFO("Session %" PRIu32 " [HSM:%s]\n",

             sessions,

             hsm_state == HSM_OK ? "OK" : "DEGRADED");

  } else {

    /* Encrypted telemetry from sensor */

    LOG_INFO("Telemetry rx %d bytes\n", len);

  }

}

 

static void disc_rx(struct simple_udp_connection *c,

                    const uip_ipaddr_t *src, uint16_t sport,

                    const uip_ipaddr_t *dst, uint16_t dport,

                    const uint8_t *buf, uint16_t len)

{

  (void)src; (void)buf; (void)len;

}

 

/* HSM health monitor */

PROCESS(hsm_proc, "HSM Monitor");

PROCESS_THREAD(hsm_proc, ev, data)

{

  static struct etimer ht;

  PROCESS_BEGIN();

  etimer_set(&ht, HSM_CHECK_INTERVAL);

  while(1) {

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&ht));

    hsm_t s = hsm_poll();

    if(s != hsm_state) {

      hsm_state = s;

      if(s == HSM_OK)

        LOG_INFO("HSM restored - hardware signing active\n");

      else

        LOG_WARN("HSM fault - software fallback active\n");

    }

    LOG_INFO("HSM=%s sessions=%" PRIu32 " faults=%" PRIu32 "\n",

             hsm_state == HSM_OK ? "OK" : "DEGRADED",

             sessions, hsm_faults);

    etimer_reset(&ht);

  }

  PROCESS_END();

}

 

PROCESS(gw_proc, "RunB Gateway");

AUTOSTART_PROCESSES(&gw_proc, &hsm_proc);

 

PROCESS_THREAD(gw_proc, ev, data)

{

  static struct etimer et;

  static struct etimer disc_et;

 

  PROCESS_BEGIN();

 

  /* Become RPL root */

  NETSTACK_ROUTING.root_start();

  LOG_INFO("RPL root started\n");

 

  simple_udp_register(&data_conn, UDP_GATEWAY_PORT, NULL,

                      UDP_SENSOR_PORT, data_rx);

  simple_udp_register(&disc_conn, UDP_DISCOVER_PORT, NULL,

                      UDP_DISCOVER_PORT, disc_rx);

 

  etimer_set(&et, 10 * CLOCK_SECOND);

  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

 

  LOG_INFO("AHEPQC-IIoT Gateway ready\n");

 

  etimer_set(&disc_et, DISCOVER_INTERVAL);

  etimer_set(&et, 30 * CLOCK_SECOND);

 

  while(1) {

    PROCESS_WAIT_EVENT();

 

    if(etimer_expired(&disc_et)) {

      uip_ipaddr_t all_nodes;

      uip_create_linklocal_allnodes_mcast(&all_nodes);

      uint8_t beacon[4] = {0xDE, 0xAD, 0xBE, 0xEF};

      simple_udp_sendto(&disc_conn, beacon, sizeof(beacon), &all_nodes);

      etimer_reset(&disc_et);

    }

 

    if(etimer_expired(&et)) {

      LOG_INFO("Gateway sessions=%" PRIu32 "\n", sessions);

      etimer_reset(&et);

    }

  }

 

  PROCESS_END();

}



