#ifndef DNSOVERTLS_INCLUDED
#define DNSOVERTLS_INCLUDED
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/ssl.h>


typedef enum{
  DNSOVERTLS_WAITING_LEN1,
  DNSOVERTLS_WAITING_LEN2,
  DNSOVERTLS_WAITING_QUERY,
  DNSOVERTLS_PROCESS_QUERY,
  DNSOVERTLS_ERROR
} dnsovertls_status_t;

/* struct to pass inbound query data to the dm_worker threads(s) */
/* note storage is allocated in the main thread and freed in the worker thread */
typedef struct dm_query {

  /* the inbound query in wire format */
  char *query;

  /* The received number of octets in this query
   * (1 DNS query can span multiple SSL packets or buffer read calls) */
  size_t query_len;

  /* The callback to send data to this client.        */
  /* expects a dns reply packet in wire format        */
  int (*packet_write)(char *response, size_t response_len);

  /* The ssl for this client. Used for checking certs versus the query*/
  SSL *ssl;

  /* The status of the DNS stream for this client. */
  dnsovertls_status_t status;

  /* The expected number of octets in this query */
  size_t expected_octets;

  /* The 1st octet of the length field (rfc7858 rfc1035) */
  unsigned char len1;

  /* The 2nd octet of the length field. SHOULD be sent with len1 but not guaranteed */
  unsigned char len2;

} dm_query_t;

int dnsovertls_write (char *response, size_t response_len);

void dm_query_free (dm_query_t *p_dm_query);

void dm_query_init (dm_query_t *p_dm_query);

dm_query_t *dm_query_new(SSL *ssl);

void dnsovertls_read (dm_query_t *p_dm_query, char *buf, size_t octets_available);
#endif // DNSOVERTLS_INCLUDED
