#include "dnsovertls.h"

/* write wire packet back to SSL. Format is per RFC7858 */
int dnsovertls_write (char *response, size_t response_len) {
  unsigned int temp=(unsigned int)response_len;
  unsigned char len2=(unsigned char) (temp & 0xff);
  unsigned char len1=(unsigned char) (temp>>8 & 0xff) ;
  printf("Sending packet length %u %02x %02x\n",(int)temp,len1,len2);
  // this isn't as recommended in RFC 7858 as it uses three separate write calls
  //result=bufferevent_write(bev,&len1,1);
  // if (result==0) printf ("written %i to buffer\n",(int)len1);
  //result=bufferevent_write(bev,&len2,1);
  // if (result==0) printf ("written %i to buffer\n",(int)len2);
  //result=bufferevent_write(bev,wire,wiresize);
  // if (result==0) printf ("written %i to buffer\n",(int)wiresize);
  //result=bufferevent_flush(bev,EV_WRITE,BEV_FLUSH);
  // if (result==1) printf ("flushed buffer\n");
  //return wiresize;
  return 1;
}

void dm_query_free (dm_query_t *p_dm_query)
{
  if (p_dm_query == NULL ) return;
  if (p_dm_query->query != NULL) {
    free(p_dm_query->query); // the inbound query packet
    p_dm_query->query=NULL;
  }
  free(p_dm_query); // the struct
  p_dm_query=NULL;
  return;
}

/* clear the dns over tls status to be ready for the next query packet */
void dm_query_reset(dm_query_t *p_dm_query)
{
  if (p_dm_query!=NULL) {
    p_dm_query->status=DNSOVERTLS_WAITING_LEN1;
    p_dm_query->query_len=0;
    p_dm_query->expected_octets=0;
    p_dm_query->len1=0;
    p_dm_query->len2=0;
    if (p_dm_query->query != NULL) {
      memset(p_dm_query->query, 0, sizeof(*p_dm_query->query));
    }
  }
}

/* new DM query */
dm_query_t *dm_query_new(SSL *ssl)
{
    dm_query_t *p_dm_query;/* Create a dm_query object. */
    p_dm_query=(dm_query_t *) malloc(sizeof(*p_dm_query));
    if (p_dm_query== NULL) {
    /* new dns query packet of length expected_octets*/
    //p_dm_query->query=(char*) malloc (p_dm_query->expected_octets);
      die ("Failed to allocate space for p_dm_query query\n");
      return NULL;
    }
    dm_query_reset(p_dm_query); // init status for a new incoming query packet
    p_dm_query->ssl=ssl;        // pointer to an existing SSL struct for certs
    return p_dm_query;
}


/* The input is a stream and it's unpredictable whether a single
 * whole DNS packet will arrive at once over SSL so we have to re-buffer
 * and convert to a stand alone DNS packet for later processing.
 * A great example of buffer bloat.
 * The inbound buffer is fixed length, so we have to consume the entire
 * content before returning. That may be more than one request */
void dnsovertls_read (dm_query_t *p_dm_query, char *buf, size_t octets_available) {
  size_t octets_read=0;      // number of octets actually read from this buf

   /* There is no way to recover from an error
   * so just pretend we've read the data      */
  if (octets_available==0 || p_dm_query->status==DNSOVERTLS_ERROR) {
    return;
  }

  while (octets_available > 0) {

    // waiting 1st char of DNS over SSL = msb length
    if (octets_available>0 && p_dm_query->status==DNSOVERTLS_WAITING_LEN1) {
      p_dm_query->len1=(unsigned char)buf[octets_read];
      octets_read++;
      octets_available--;
      p_dm_query->status=DNSOVERTLS_WAITING_LEN2;
      printf("Received %zu octet. Set len1 to %d.\n",octets_read,(int)p_dm_query->len1);
    }
    // waiting 2nd char of DNS over SSL = lsb length
    if (octets_available>0 && p_dm_query->status==DNSOVERTLS_WAITING_LEN2) {
      p_dm_query->len2=(unsigned char)buf[octets_read];
      octets_read++;
      octets_available--;

      // set up a query buffer now we know the expected length
      p_dm_query->expected_octets= p_dm_query->len1 <<8;
      p_dm_query->expected_octets+= p_dm_query->len2;
      printf("Set expected_octets %zu len1 %d len2 %d.\n",p_dm_query->expected_octets,(int)p_dm_query->len1,(int)p_dm_query->len2);

      p_dm_query->query_len=0;
      p_dm_query->status=DNSOVERTLS_WAITING_QUERY;

      // Create a packet buffer for the inbound request.
      // uses realloc as it's in a loop.
      char *p_tmp;
      p_tmp=(char *)realloc(p_dm_query->query, p_dm_query->expected_octets);
      if (p_tmp == NULL){
        die ("Failed to allocate space for p_dm_query->query query packet\n");
      }
      p_dm_query->query=p_tmp;
      memset(p_dm_query->query, 0, sizeof(*p_dm_query->query));
    }

    // Read as many expected octets as needed to complete the query
    if (octets_available>0 && p_dm_query->status==DNSOVERTLS_WAITING_QUERY) {
      size_t octets_to_copy;
      size_t octets_needed;
      // Are there more available than needed? Then only copy needed.
      // Otherwise copy what is available.
      octets_needed=p_dm_query->expected_octets-p_dm_query->query_len;
      octets_to_copy =(octets_needed<octets_available ? octets_needed : octets_available);
      memcpy(p_dm_query->query+p_dm_query->query_len, buf+octets_read, octets_to_copy);
      octets_read+=octets_to_copy;
      p_dm_query->query_len+=octets_to_copy;
      octets_available-=octets_to_copy;

      printf("query_len %zu Expected %zu Read %zu left over %zu.\n",p_dm_query->query_len,p_dm_query->expected_octets,octets_read,octets_available);
    } //read all

    // Do we have a query ready for dispatch?
    if (p_dm_query->status==DNSOVERTLS_WAITING_QUERY && p_dm_query->expected_octets==p_dm_query->query_len) {
      printf("Query ready for dispatch\n");
      p_dm_query->status=DNSOVERTLS_PROCESS_QUERY;

      /* dispatch this query to the DM worker.
       * At the moment there is only a single worker per client.
       * That seems sensible given that DNS operations can also write
       * and change the state of the zone for future queries.         */
      dm_worker(p_dm_query);
      // Reset the query for the next query in the stream.
      // Assuming that there is one.
      dm_query_reset(p_dm_query);
    } //dispatch
    printf("Status %i\n", (int)p_dm_query->status);
  } // while
} 
