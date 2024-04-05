/* switch on the additional SSL code in libevent-cb.c */
#ifndef WITH_SSL
#define WITH_SSL
#endif // WITH_SSL

#include "libevent-cb.h"
/**
 *  Main function for demonstrating the echo server.
 *  You can remove this and simply call runServer() from your application. 
 */
int main(int argc, char *argv[]) {
    int port = (argc > 1 && atoi(argv[1]) > 0) ? atoi(argv[1]) : DEFULT_SERVER_PORT;
#ifdef WITH_SSL
    printf("Running with SSL support.\n");
#endif // WITH_SSL

    return runServer(port);
}
