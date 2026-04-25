/*

 * project-conf.h

 * AHEPQC-IIoT Final Version

 */

 

#ifndef PROJECT_CONF_H_

#define PROJECT_CONF_H_

 

/* Network ports */

#define UDP_SENSOR_PORT    8765

#define UDP_GATEWAY_PORT   5678

#define UDP_DISCOVER_PORT  9999   /* gateway discovery */

 

/* Simulation settings */

#define SEND_INTERVAL      (20 * CLOCK_SECOND)

#define DISCOVER_INTERVAL  (5  * CLOCK_SECOND)

#define MAX_ROUNDS         30

 

/* PQC message sizes - NIST FIPS 203/204 */

#define MLKEM512_PK        800

#define MLKEM512_CT        768

#define DILITHIUM2_SIG     2420

#define CERT_OVERHEAD      64

#define AES256_KEY         32

#define AES256_IV          12

#define AES256_TAG         16

#define TELEMETRY_SIZE     32

 

/* Firmware update time - static metric */

#define FIRMWARE_UPDATE_S  17

 

/* Key/sig sizes per session */

#define RUN_A_KEY_SIG_B    4532   /* KEM_PK + DIL2_SIG + DIL2_PK */

#define RUN_B_KEY_SIG_B    800    /* KEM_PK only */

 

/* Crypto latency models (ms) - Shahid et al. 2026 */

/* Run A: ECDH(10ms) + KEM(0.04ms) + Dilithium2(0.45ms) = ~11ms */

#define RUN_A_CRYPTO_MS    11

/* Run B: KEM only (0.02ms) = ~1ms */

#define RUN_B_CRYPTO_MS    1

 

/* RAM model (bytes) - Astarloa et al. IoT 2025 */

#define RAM_MLKEM512       14336

#define RAM_DILITHIUM2     40960

#define RAM_ECDH           5120

#define RAM_AES256         512

#define RAM_PROTOCOL       2048

 

/* Metric log tags */

#define TAG_LAT  "M_LAT"

#define TAG_NRG  "M_NRG"

#define TAG_RAM  "M_RAM"

#define TAG_TXB  "M_TXB"

#define TAG_THR  "M_THR"

#define TAG_PKT  "M_PKT"

#define TAG_RND  "M_RND"

 
#ifndef UIP_CONF_BUFFER_SIZE
#define UIP_CONF_BUFFER_SIZE        4096
#endif
#ifndef SICSLOWPAN_CONF_FRAG
#define SICSLOWPAN_CONF_FRAG        1
#endif
#ifndef SICSLOWPAN_CONF_MAXAGE
#define SICSLOWPAN_CONF_MAXAGE      8
#endif

#endif /* PROJECT_CONF_H_ */




