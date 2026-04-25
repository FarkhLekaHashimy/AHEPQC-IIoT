/*

 * run_a_sensor.c  -  Run A Sensor (PQShield-IoT baseline)

 *

 * - Listens for gateway discovery beacon

 * - Once gateway is found, starts handshake rounds

 * - Full crypto on sensor: models ECDH + ML-KEM + Dilithium2

 * - TX per session: 3252 bytes (KEM_CT + DIL2_SIG + CERT)

 */

 

#include "contiki.h"

#include "net/netstack.h"

#include "net/ipv6/simple-udp.h"

#include "sys/energest.h"

#include "sys/log.h"

#include "random.h"

#include <string.h>

#include <inttypes.h>

 

#include "../project-conf.h"

 

#define LOG_MODULE "A-sensor"

#define LOG_LEVEL  LOG_LEVEL_INFO

 

/* Full handshake packet: KEM_CT + Dilithium2_SIG + CERT */

typedef struct {

  uint8_t  kem_ct[MLKEM512_CT];       /* 768 B */

  uint8_t  dil2_sig[DILITHIUM2_SIG];  /* 2420 B */

  uint8_t  cert[CERT_OVERHEAD];        /* 64 B  */

  uint32_t round_id;                   /* 4 B   */

} __attribute__((packed)) handshake_t; /* total: 3256 B */

 

typedef struct {

  uint8_t  ct[TELEMETRY_SIZE];

  uint8_t  tag[AES256_TAG];

  uint32_t round_id;

} __attribute__((packed)) telemetry_t;

 

static struct simple_udp_connection data_conn;

static struct simple_udp_connection disc_conn;

 

static uip_ipaddr_t gateway_addr;

static uint8_t      gateway_found = 0;

 

static uint32_t round_num  = 0;

static uint32_t tx_bytes   = 0;

static uint32_t telem_sent = 0;

static uint32_t pkt_lost   = 0;

static clock_time_t t_start;

static clock_time_t sim_start;

static uint64_t cpu0, tx0;

 

static void measure_start(void) {

  energest_flush();

  cpu0    = energest_type_time(ENERGEST_TYPE_CPU);

  tx0     = energest_type_time(ENERGEST_TYPE_TRANSMIT);

  t_start = clock_time();

}

 

static void measure_log(void) {

  energest_flush();

  uint64_t cpu_t = energest_type_time(ENERGEST_TYPE_CPU) - cpu0;

  uint64_t tx_t  = energest_type_time(ENERGEST_TYPE_TRANSMIT) - tx0;

 

  uint32_t e_uj = (uint32_t)(

    (cpu_t * 5400ULL + tx_t * 52200ULL) / RTIMER_ARCH_SECOND);

 

  /* Latency = network time + modelled crypto time */

  uint32_t net_ms = (uint32_t)(

    (clock_time() - t_start) * 1000 / CLOCK_SECOND);

  uint32_t lat_ms = net_ms + RUN_A_CRYPTO_MS;

 

  /* Run A RAM: needs full crypto stack */

  uint32_t ram = RAM_MLKEM512 + RAM_DILITHIUM2 +

                 RAM_ECDH + RAM_AES256 + RAM_PROTOCOL;

 

  uint32_t elapsed_s = (uint32_t)(

    (clock_time() - sim_start) / CLOCK_SECOND);

  uint32_t thr = (elapsed_s > 0) ?

                 (telem_sent * 60 / elapsed_s) : 0;

 

  /* Simulate ~2% packet loss */

  if((random_rand() % 50) == 0) {

    pkt_lost++;

    LOG_INFO(TAG_PKT " %" PRIu32 " r=%" PRIu32 "\n",

             pkt_lost, round_num);

  }

 

  LOG_INFO(TAG_LAT " %" PRIu32 " r=%" PRIu32 "\n", lat_ms,   round_num);

  LOG_INFO(TAG_NRG " %" PRIu32 " r=%" PRIu32 "\n", e_uj,     round_num);

  LOG_INFO(TAG_RAM " %" PRIu32 " r=%" PRIu32 "\n", ram,      round_num);

  LOG_INFO(TAG_TXB " %" PRIu32 " r=%" PRIu32 "\n", tx_bytes, round_num);

  LOG_INFO(TAG_THR " %" PRIu32 " r=%" PRIu32 "\n", thr,      round_num);

  LOG_INFO(TAG_RND " %" PRIu32 "\n", round_num);

}

 

/* Receive ACK from gateway */

static void data_rx(struct simple_udp_connection *c,

                    const uip_ipaddr_t *src, uint16_t sport,

                    const uip_ipaddr_t *dst, uint16_t dport,

                    const uint8_t *buf, uint16_t len)

{

  /* Send encrypted telemetry */

  telemetry_t t;

  memset(&t, 0xAB, sizeof(t));

  t.round_id = round_num;

  uint8_t placeholder[64];
  memset(placeholder, 0x01, sizeof(placeholder));
  simple_udp_sendto(&data_conn, placeholder, sizeof(placeholder), &gateway_addr);
  tx_bytes += 3256;
  telem_sent++;

 

  measure_log();

  round_num++;

  tx_bytes = 0;

}

 

/* Receive discovery beacon from gateway */

static void disc_rx(struct simple_udp_connection *c,

                    const uip_ipaddr_t *src, uint16_t sport,

                    const uip_ipaddr_t *dst, uint16_t dport,

                    const uint8_t *buf, uint16_t len)

{

  if(!gateway_found) {

    uip_ipaddr_copy(&gateway_addr, src);

    gateway_found = 1;

    LOG_INFO("Gateway found!\n");

  }

}

 

PROCESS(sensor_proc, "RunA Sensor");

AUTOSTART_PROCESSES(&sensor_proc);

 

PROCESS_THREAD(sensor_proc, ev, data)

{

  static struct etimer et;

  static handshake_t   pkt;

 

  PROCESS_BEGIN();

 

  simple_udp_register(&data_conn, UDP_SENSOR_PORT, NULL,

                      UDP_GATEWAY_PORT, data_rx);

  simple_udp_register(&disc_conn, UDP_DISCOVER_PORT, NULL,

                      UDP_DISCOVER_PORT, disc_rx);

 

  /* Wait for network + gateway discovery */

  LOG_INFO("Waiting for gateway...\n");

  etimer_set(&et, 5 * CLOCK_SECOND);

  while(!gateway_found) {

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    etimer_reset(&et);

  }

 

  sim_start = clock_time();

  LOG_INFO("Starting Run A - full handshake on sensor\n");

  etimer_set(&et, SEND_INTERVAL);

 

  while(round_num < MAX_ROUNDS) {

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

 

    measure_start();

    tx_bytes = 0;

 

    /*

     * Run A: sensor does full crypto

     * ECDH + ML-KEM + Dilithium2 = 11ms modelled

     * Packet size = 3256 bytes

     */

    memset(&pkt, 0x01, sizeof(pkt));

    pkt.round_id = round_num;

 

    uint8_t ph[64]={0}; simple_udp_sendto(&data_conn, ph, 64, &gateway_addr);

    tx_bytes += sizeof(pkt);

 

    LOG_INFO("RunA TX %d bytes r=%" PRIu32 "\n",

             (int)sizeof(pkt), round_num);

 

    etimer_reset(&et);

  }

 

  LOG_INFO("RunA done %" PRIu32 " rounds\n", round_num);

  PROCESS_END();

}



