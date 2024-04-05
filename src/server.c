#include "libevent-cb.h"
/**
 *  Main function for demonstrating the echo server.
 *  You can remove this and simply call runServer() from your application. 
 */
int main(int argc, char *argv[]) {
    int port = argc > 1 && atoi(argv[1]) > 0 ? : DEFULT_SERVER_PORT;
    return runServer(port);
}
