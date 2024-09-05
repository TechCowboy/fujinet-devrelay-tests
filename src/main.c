#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <signal.h>

#define PACKET_SIZE (512)
#define MAX_MESSAGE_SIZE (PACKET_SIZE * 2)

char Spoofed_AppleWin_hostname[80] = {"localhost"};
int  Spoofed_AppleWin_port         = 1985;
char Real_AppleWin_hostname[80]    = {"fujinet-vm.local"};
int  Real_AppleWin_port            = 1985;

int spoofed_applewin = 0;
int fujinet_connection = 0;
int real_applewin = 0;

int stop = 0;

char filename[] = { "snoopy.cfg"};

typedef struct ARGUMENTS
{
    pthread_t id;
    int  *in_connection;
    int  *out_connection;
    char *in_msg;
    char *out_msg;
    int  *stop;
    int  stopped;
} ARGUMENTS;

/* Signal Handler for SIGINT */
void sigintHandler(int sig_num)
{
    /* Reset handler to catch SIGINT next time.
    Refer http://en.cppreference.com/w/c/program/signal */
    signal(SIGINT, sigintHandler);

    if (spoofed_applewin)
    {
        printf("\nClosing Spoofed AppleWin Connection\n");
        close(spoofed_applewin);
    }
    if (fujinet_connection)
    {
        printf("\nClosing FujiNet Connection\n");
        close(fujinet_connection);
    }

    if (real_applewin)
    {
        printf("\nClosing Real AppleWin Connection\n");
        close(real_applewin);
    }
    exit(-1);

    
}

void *threaded_forward(void *p)
{
    ARGUMENTS *a = (ARGUMENTS *)p;
    char slip_message[MAX_MESSAGE_SIZE];
    ssize_t bytes_read = 0;
    struct timeval timeout;
    char c;


    printf("Forward messages from %s -> %s\n", a->in_msg, a->out_msg);

    // timeout if we wait more than a second.
    // this is so the thread knows to stop.
    timeout.tv_sec  = 1;
    timeout.tv_usec = 0;

    if (setsockopt(*a->in_connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        printf("setsockopt failed\n");
    }


    while (*a->stop == 0)
    {
        // get message from client
        bytes_read = read(*a->in_connection, slip_message, sizeof(slip_message) - 1);
        if (bytes_read > 0)
        {
            if (send(*a->out_connection, slip_message, bytes_read, 0) == -1)
            {
                printf("%s - send failed\n", a->out_msg);
                break;
            }

            printf("%s -> %s ", a->in_msg, a->out_msg);
   
            for (int i = 0; i < bytes_read; i++)
            {
                printf("%02x ", slip_message[i] & 0xFF);
            }
            printf("\n");
            printf("%s -> %s ", a->in_msg, a->out_msg);
            for (int i = 0; i < bytes_read; i++)
            {
                c = slip_message[i] & 0xFF;
                if ((c<' ') || (c>'z'))
                    printf(" . ", c);
                else
                    printf(" %c ", c);
            }
            printf("\n");

        }
        else
        {
            if (bytes_read == 0)
            {
                printf("%s - Connection Lost\n", a->in_msg);
                break;
            }
            else
            {
                if (errno != EAGAIN)
                {
                    printf("%s - bytes_read: %d   errno: %d\n", a->in_msg, bytes_read, errno);
                    sleep(1);
                }
            }
        }
    }
    close(*a->in_connection);
    *a->in_connection = 0;

    printf("%s Forwarder Exiting...\n", a->in_msg);
    *a->stop   = 1; // ask all forward threads to stop
    a->stopped = 1;
    return NULL;
}


void get_host_and_port(char *line, char *host, int *port)
{
    char *p;

    p = strchr(line, ':');
    *p = '\0';
    strcpy(host, line);
    p++;
    *port = atoi(p);
}


int get_hosts_from_file(void)
{
    FILE *fp;
    char line[80];

    fp = fopen(filename, "r");
    if (fp != NULL)
    {
        if (fgets(line, sizeof(line), fp) != NULL)
            get_host_and_port(line, Spoofed_AppleWin_hostname, &Spoofed_AppleWin_port);

        if (fgets(line, sizeof(line), fp) != NULL)
            get_host_and_port(line, Real_AppleWin_hostname, &Real_AppleWin_port);

        printf("Got config %s:\n", filename);

        fclose(fp);
        return 0;
    } else
    {
        printf("No %s config file\n", filename);
        return -1;
    }

}

int lookup_host(char *host, char *ip_address, bool ipv4)
{
    struct addrinfo hints, *res, *result;
    int errcode;
    char addrstr[100];
    void *ptr;
    bool ipv4entry = true;
    bool no_entry;

    strcpy(ip_address, "");

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    errcode = getaddrinfo(host, NULL, &hints, &result);
    if (errcode != 0)
    {
        perror("getaddrinfo");
        return -1;
    }

    res = result;

    while (res)
    {
        no_entry = false;
        inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 100);

        switch (res->ai_family)
        {
        case AF_INET:
            ipv4entry = true;
            ptr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
            break;
        case AF_INET6:
            ipv4entry = false;
            ptr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
            break;
        default:
            no_entry = true;
        }
        if (! no_entry)
        {
            inet_ntop(res->ai_family, ptr, addrstr, 100);
            if (ipv4 == ipv4entry)
            {
                strcpy(ip_address, addrstr);
            }
            //printf("IPv%d address: %s (%s)\n", res->ai_family == PF_INET6 ? 6 : 4,
            //       addrstr, res->ai_canonname);
        }
        res = res->ai_next;
    }

    freeaddrinfo(result);

    return 0;
}





int main(int arc, char **argv)
{
    char hostname[20] = {""};
    char local_ip[20] = {""};
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    ARGUMENTS thread1_args;
    ARGUMENTS thread2_args;
    int status;
    char address_str[INET6_ADDRSTRLEN];
    int opt = 1;

    stop = 0;
    /* Set the SIGINT (Ctrl-C) signal handler to sigintHandler
       Refer http://en.cppreference.com/w/c/program/signal */
    signal(SIGINT, sigintHandler);


    gethostname(hostname, sizeof(hostname));
    printf("Hostname: %s\n", hostname);

    lookup_host(hostname, local_ip, true);
 
    
    get_hosts_from_file();
    printf(
    
"                                 ...............\n"
"                             ....              ..\n"
"                            ..                   ..\n"
"                           ..                      ..\n"
"                         ...                        ..\n"
"            .............       ***                  ..\n"
"          ..                   *****                  $.\n"
"    @@@@@@                      ***     $              $\n"
"   @     @                             $   $$$$$$$$    $\n"
"  @@@@@@@@                            $   $$$$$$$$$$   $\n"
"   @@@@@@@                           $   $$$$$$$$$$$   $\n"
"    @@@@@@                           $   $$$$$$$$$$$   $\n"
"          ...                        $   $$$$$$$$$$    $\n"
"            .............            $$    $$$$$$$   $$\n"
"                        ..        ...  $$          $$\n"
"                        ..       ..     $$      $$$\n"
"                        ..       ..      $$$$$$$$\n"
"                        =============\n"
"                        =============\n"
    );


    printf("Protocol Snooper - Snoopy - By Norman Davie\n");
    printf("Messages received at: %s:%d (fujinet connects here)\n", Spoofed_AppleWin_hostname, Spoofed_AppleWin_port);
    printf("will be forwarded to: %s:%d (Real AppleWin)\n", Real_AppleWin_hostname, Real_AppleWin_port);
    printf("and vice versa\n");
    printf("hostname: %s   IP: %s\n", hostname, local_ip);

    while (true)
    {
        printf("FujiNet        Snoopy        RealAppleWin\n\n");
        printf("Waiting for fujinet to connect here: %s:%d <Spoofed AppleWin - this application>\n", Spoofed_AppleWin_hostname, Spoofed_AppleWin_port);


        // We are a server

        stop = 0;
        while (true)
        {
            // create the socket
            if ((spoofed_applewin = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            {
                continue;
            } 


            // Forcefully attaching socket to the port 
            if (setsockopt(spoofed_applewin, SOL_SOCKET,
                        SO_REUSEADDR , &opt,
                        sizeof(opt)))
            {
                printf("Could not force reuse of address for spoofed applewin\n");
                exit(EXIT_FAILURE);
            }

            // accept a connection from anywhere on Spoofed_AppleWin_port
            memset(&address, 0, sizeof(address));
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = INADDR_ANY;
            address.sin_port = htons(Spoofed_AppleWin_port);

            // When a socket has both an IP address and a port number 
            // it is said to be 'bound to a port', or 'bound to an address'. 
            // A bound socket can receive data because it has a complete address. 
            // The process of allocating a port number to a socket is 
            // called 'binding'.
            if (bind(spoofed_applewin, (struct sockaddr *)&address, sizeof(address)) < 0)
            {
                continue;
            } else
            {
                break;
            }
        } // while not bound

        // listen() marks the socket referred to by spoofed_applewin as a passive
        // socket, that is, as a socket that will be used to accept
        // incoming connection requests using accept(2).

        if (listen(spoofed_applewin, 3) < 0)
        {
            printf("Spoofed AppleWin Listen failed\n");
            exit(-1);
        }
        
        if ((fujinet_connection = accept(spoofed_applewin, (struct sockaddr *)&address, &addrlen)) < 0)
        {
            printf("Accept fujinet connection failed\n");
            exit(-2);
        }

        // convert the received ip address to a string
        inet_ntop(AF_INET, &(address.sin_addr), address_str, INET_ADDRSTRLEN);

        printf("\n*** Received connection from Fujinet (%s:%d) ***\n\n", address_str, address.sin_port);

        printf("FujiNet <----> Snoopy        RealAppleWin\n\n");
        printf("Attempting to connect to REAL AppleWin %s:%d\n", Real_AppleWin_hostname, Real_AppleWin_port);

        // connect as a client
        while(true)
        {
            // create a socket
            if ((real_applewin = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            {
                sleep(1);
                continue;
            } else
                break;
        }


        // get the ip of our hostname
        lookup_host(Real_AppleWin_hostname, address_str, true);

        // build up the address structure
        memset(&address, '\0', sizeof(address));

        // Convert IPv4 and IPv6 addresses from text to binary
        // form
        if (inet_pton(AF_INET, address_str, &address.sin_addr) <= 0)
        {
            printf("\nInvalid address/ Address not supported \n");
            exit(-3);
        }

        // internet address
        address.sin_family = AF_INET;
        // selected port
        address.sin_port = htons(Real_AppleWin_port);

        while(true)
        {
            // try and connect!
            if ((status = connect(real_applewin, (struct sockaddr *)&address, sizeof(address))) < 0)
            {
                sleep(1);
            } else
                break;
        }

        printf("\nConnected to Real AppleWin %s:%d\n\n", Real_AppleWin_hostname, Real_AppleWin_port);
        printf("FujiNet <----> Snoopy <----> RealAppleWin\n\n");
        printf("**** Snooping has begun! ****\n");

        thread1_args.id = 1;
        thread1_args.in_connection  = &fujinet_connection;
        thread1_args.out_connection = &real_applewin;
        thread1_args.in_msg  = " FujiNet";
        thread1_args.out_msg = "AppleWin";
        thread1_args.stop    = &stop;
        thread1_args.stopped = 0;

        thread1_args.id = 2;
        thread2_args.in_connection  = &real_applewin;
        thread2_args.out_connection = &fujinet_connection;
        thread2_args.in_msg  = "AppleWin";
        thread2_args.out_msg = " FujiNet";
        thread2_args.stop    = &stop;
        thread2_args.stopped = 0;


        pthread_create(&thread1_args.id, NULL, threaded_forward, &thread1_args);
        pthread_create(&thread2_args.id, NULL, threaded_forward, &thread2_args);

        while((thread1_args.stopped + thread2_args.stopped) != 2)
        {
            sleep(10);
        }
        printf("Threads stopped\n");

        printf("Closing...\n");

        // closing the connected socket
        if (spoofed_applewin)
        {
            printf("Closing Spoofed AppleWin Connection\n");
            close(spoofed_applewin);
        }

        if (fujinet_connection)
        {
            printf("Closing FujiNet Connection\n");
           close(fujinet_connection);
        }

        if (real_applewin)
        {
            printf("Closing AppleWin Connection\n");
            close(real_applewin);
        }    
    }
}

/*
AppleWin ->  FujiNet c0 8e 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 8e 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 8f 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 8f 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 90 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 90 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 91 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 91 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 92 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 92 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 93 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 93 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 94 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 94 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 95 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 95 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 96 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 96 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 97 01 01 00 02 28 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  (  .  .  .
 FujiNet -> AppleWin c0 97 00 00 00 e1 a2 02 10 22 00 00 e1 a2 02 03 22 00 00 e1 38 fb 68 d0 1b ae 00 02 a9 2f dd 00 02 f0 05 ca d0 f8 80 0c ca 8e 00 02 20 00 bf c6 53 12 a9 00 60 18 fb c2 10 a2 06 20 20 3f 11 38 fb 20 00 bf c4 72 12 90 0c 18 fb c2 30 20 ec 10 90 ed 38 fb 38 60 01 00 02 03 80 02 00 1c 00 02 00 00 00 00 04 00 00 20 00 00 00 00 01 00 04 00 00 00 00 00 00 0a 00 0f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1b 43 61 6e 27 74 20 72 75 6e 20 6e 65 78 74 20 61 70 70 6c 69 63 61 74 69 6f 6e 2e 14 50 72 6f 44 4f 53 20 45 72 72 6f 72 20 3d 20 24 20 20 20 20 00 17 50 6c 65 61 73 65 20 69 6e 73 65 72 74 20 74 68 65 20 64 69 73 6b 3a 0d 41 63 63 65 70 74 3a 20 1b 0f 4d 0e 18 0b 43 61 6e 63 65 6c 3a 20 45 73 63 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  .  "  .  .  .  .  .  .  "  .  .  .  8  .  h  .  .  .  .  .  .  /  .  .  .  .  .  .  .  .  .  .  .  .  .  .     .  .  .  S  .  .  .  `  .  .  .  .  .  .        ?  .  8  .     .  .  .  r  .  .  .  .  .  .  0     .  .  .  .  8  .  8  `  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .     .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  C  a  n  '  t     r  u  n     n  e  x  t     a  p  p  l  i  c  a  t  i  o  n  .  .  P  r  o  D  O  S     E  r  r  o  r     =     $              .  .  P  l  e  a  s  e     i  n  s  e  r  t     t  h  e     d  i  s  k  :  .  A  c  c  e  p  t  :     .  .  M  .  .  .  C  a  n  c  e  l  :     E  s  c  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 98 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 98 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 99 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 99 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 9a 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 9a 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 9b 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 9b 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 9c 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 9c 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 9d 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 9d 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 9e 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 9e 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 9f 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 9f 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 a0 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a0 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 a1 00 01 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a1 00 fc 18 01 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 a2 00 03 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a2 00 ec 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 a3 00 04 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a3 00 ec 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 a4 00 05 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a4 00 30 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .
AppleWin ->  FujiNet c0 a5 00 06 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a5 00 10 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 a6 00 07 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a6 00 30 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .
AppleWin ->  FujiNet c0 a7 00 08 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a7 00 70 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .
AppleWin ->  FujiNet c0 a8 00 09 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a8 00 70 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .
AppleWin ->  FujiNet c0 a9 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a9 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 aa 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 aa 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 ab 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ab 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 ac 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ac 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 ad 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ad 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 ae 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ae 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 af 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 af 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 b0 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b0 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 b1 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b1 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 b2 01 01 00 02 02 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b2 00 00 00 03 00 fa 49 53 53 54 52 41 43 4b 45 52 00 00 00 00 00 00 00 d0 2c 02 12 00 00 d0 2c 02 12 00 00 e3 27 0d 04 00 06 00 18 01 26 50 52 4f 44 4f 53 00 00 00 00 00 00 00 00 00 ff 07 00 22 00 e8 42 00 2d 24 09 09 00 00 21 00 00 32 24 00 07 02 00 2f 46 4e 2e 43 4c 4f 43 4b 2e 53 59 53 54 45 4d ff 2a 00 04 00 21 04 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 1c 43 4c 4f 43 4b 2e 53 59 53 54 45 4d 00 00 00 ff 2d 00 01 00 cb 01 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 25 43 4c 4f 43 4b 00 00 00 00 00 00 00 00 00 00 06 2f 00 0e 00 96 18 00 78 2e 37 17 00 00 c3 00 40 78 2e 37 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  I  S  S  T  R  A  C  K  E  R  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  ,  .  .  .  .  .  '  .  .  .  .  .  .  .  &  P  R  O  D  O  S  .  .  .  .  .  .  .  .  .  .  .  .  "  .  .  B  .  -  $  .  .  .  .  !  .  .  2  $  .  .  .  .  /  F  N  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  *  .  .  .  !  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  .  .  .  -  .  .  .  .  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  %  C  L  O  C  K  .  .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  x  .  7  .  .  .  .  .  @  x  .  7  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 b3 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b3 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 b4 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b4 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 b5 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b5 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 b6 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b6 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 b7 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b7 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 b8 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b8 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 b9 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b9 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 ba 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ba 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 bb 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 bb 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 bc 01 01 00 02 02 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 bc 00 00 00 03 00 fa 49 53 53 54 52 41 43 4b 45 52 00 00 00 00 00 00 00 d0 2c 02 12 00 00 d0 2c 02 12 00 00 e3 27 0d 04 00 06 00 18 01 26 50 52 4f 44 4f 53 00 00 00 00 00 00 00 00 00 ff 07 00 22 00 e8 42 00 2d 24 09 09 00 00 21 00 00 32 24 00 07 02 00 2f 46 4e 2e 43 4c 4f 43 4b 2e 53 59 53 54 45 4d ff 2a 00 04 00 21 04 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 1c 43 4c 4f 43 4b 2e 53 59 53 54 45 4d 00 00 00 ff 2d 00 01 00 cb 01 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 25 43 4c 4f 43 4b 00 00 00 00 00 00 00 00 00 00 06 2f 00 0e 00 96 18 00 78 2e 37 17 00 00 c3 00 40 78 2e 37 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  I  S  S  T  R  A  C  K  E  R  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  ,  .  .  .  .  .  '  .  .  .  .  .  .  .  &  P  R  O  D  O  S  .  .  .  .  .  .  .  .  .  .  .  .  "  .  .  B  .  -  $  .  .  .  .  !  .  .  2  $  .  .  .  .  /  F  N  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  *  .  .  .  !  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  .  .  .  -  .  .  .  .  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  %  C  L  O  C  K  .  .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  x  .  7  .  .  .  .  .  @  x  .  7  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 bd 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 bd 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 be 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 be 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 bf 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 bf 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 db dc 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 db dc 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 c1 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c1 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 c2 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c2 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 c3 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c3 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 c4 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c4 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 c5 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c5 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 c6 01 01 00 02 02 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c6 00 00 00 03 00 fa 49 53 53 54 52 41 43 4b 45 52 00 00 00 00 00 00 00 d0 2c 02 12 00 00 d0 2c 02 12 00 00 e3 27 0d 04 00 06 00 18 01 26 50 52 4f 44 4f 53 00 00 00 00 00 00 00 00 00 ff 07 00 22 00 e8 42 00 2d 24 09 09 00 00 21 00 00 32 24 00 07 02 00 2f 46 4e 2e 43 4c 4f 43 4b 2e 53 59 53 54 45 4d ff 2a 00 04 00 21 04 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 1c 43 4c 4f 43 4b 2e 53 59 53 54 45 4d 00 00 00 ff 2d 00 01 00 cb 01 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 25 43 4c 4f 43 4b 00 00 00 00 00 00 00 00 00 00 06 2f 00 0e 00 96 18 00 78 2e 37 17 00 00 c3 00 40 78 2e 37 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  I  S  S  T  R  A  C  K  E  R  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  ,  .  .  .  .  .  '  .  .  .  .  .  .  .  &  P  R  O  D  O  S  .  .  .  .  .  .  .  .  .  .  .  .  "  .  .  B  .  -  $  .  .  .  .  !  .  .  2  $  .  .  .  .  /  F  N  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  *  .  .  .  !  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  .  .  .  -  .  .  .  .  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  %  C  L  O  C  K  .  .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  x  .  7  .  .  .  .  .  @  x  .  7  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 c7 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c7 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 c8 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c8 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 c9 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c9 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 ca 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ca 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 cb 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 cb 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 cc 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 cc 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 cd 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 cd 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 ce 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ce 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 cf 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 cf 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 d0 01 01 00 02 03 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d0 00 02 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 d1 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d1 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 d2 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d2 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 d3 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d3 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 d4 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d4 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 d5 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d5 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 d6 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d6 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 d7 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d7 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 d8 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d8 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 d9 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d9 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 da 01 01 00 02 04 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 da 00 03 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 db dd 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 db dd 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 dc 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 dc 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 dd 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 dd 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 de 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 de 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 df 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 df 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 e0 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e0 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 e1 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e1 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 e2 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e2 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 e3 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e3 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 e4 01 01 00 02 05 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e4 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 e5 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e5 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 e6 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e6 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 e7 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e7 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 e8 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e8 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 e9 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e9 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 ea 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ea 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 eb 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 eb 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 ec 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ec 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 ed 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ed 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 ee 01 01 00 02 02 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ee 00 00 00 03 00 fa 49 53 53 54 52 41 43 4b 45 52 00 00 00 00 00 00 00 d0 2c 02 12 00 00 d0 2c 02 12 00 00 e3 27 0d 04 00 06 00 18 01 26 50 52 4f 44 4f 53 00 00 00 00 00 00 00 00 00 ff 07 00 22 00 e8 42 00 2d 24 09 09 00 00 21 00 00 32 24 00 07 02 00 2f 46 4e 2e 43 4c 4f 43 4b 2e 53 59 53 54 45 4d ff 2a 00 04 00 21 04 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 1c 43 4c 4f 43 4b 2e 53 59 53 54 45 4d 00 00 00 ff 2d 00 01 00 cb 01 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 25 43 4c 4f 43 4b 00 00 00 00 00 00 00 00 00 00 06 2f 00 0e 00 96 18 00 78 2e 37 17 00 00 c3 00 40 78 2e 37 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  I  S  S  T  R  A  C  K  E  R  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  ,  .  .  .  .  .  '  .  .  .  .  .  .  .  &  P  R  O  D  O  S  .  .  .  .  .  .  .  .  .  .  .  .  "  .  .  B  .  -  $  .  .  .  .  !  .  .  2  $  .  .  .  .  /  F  N  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  *  .  .  .  !  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  .  .  .  -  .  .  .  .  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  %  C  L  O  C  K  .  .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  x  .  7  .  .  .  .  .  @  x  .  7  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 ef 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ef 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 f0 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f0 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 f1 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f1 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 f2 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f2 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 f3 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f3 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 f4 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f4 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 f5 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f5 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 f6 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f6 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 f7 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f7 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 f8 01 01 00 02 02 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f8 00 00 00 03 00 fa 49 53 53 54 52 41 43 4b 45 52 00 00 00 00 00 00 00 d0 2c 02 12 00 00 d0 2c 02 12 00 00 e3 27 0d 04 00 06 00 18 01 26 50 52 4f 44 4f 53 00 00 00 00 00 00 00 00 00 ff 07 00 22 00 e8 42 00 2d 24 09 09 00 00 21 00 00 32 24 00 07 02 00 2f 46 4e 2e 43 4c 4f 43 4b 2e 53 59 53 54 45 4d ff 2a 00 04 00 21 04 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 1c 43 4c 4f 43 4b 2e 53 59 53 54 45 4d 00 00 00 ff 2d 00 01 00 cb 01 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 25 43 4c 4f 43 4b 00 00 00 00 00 00 00 00 00 00 06 2f 00 0e 00 96 18 00 78 2e 37 17 00 00 c3 00 40 78 2e 37 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  I  S  S  T  R  A  C  K  E  R  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  ,  .  .  .  .  .  '  .  .  .  .  .  .  .  &  P  R  O  D  O  S  .  .  .  .  .  .  .  .  .  .  .  .  "  .  .  B  .  -  $  .  .  .  .  !  .  .  2  $  .  .  .  .  /  F  N  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  *  .  .  .  !  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  .  .  .  -  .  .  .  .  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  %  C  L  O  C  K  .  .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  x  .  7  .  .  .  .  .  @  x  .  7  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 f9 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f9 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 fa 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 fa 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 fb 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 fb 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 fc 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 fc 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 fd 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 fd 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 fe 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 fe 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 ff 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ff 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 00 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 00 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 01 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 01 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 02 01 01 00 02 2a 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  *  .  .  .
 FujiNet -> AppleWin c0 02 00 29 2b 2c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  )  +  ,  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 03 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 03 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 04 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 04 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 05 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 05 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 06 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 06 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 07 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 07 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 08 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 08 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 09 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 09 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 0a 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 0a 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 0b 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 0b 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 0c 01 01 00 02 29 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  )  .  .  .
 FujiNet -> AppleWin c0 0c 00 4c 06 20 0c 04 16 a2 05 a0 00 b9 1f 20 99 00 10 c8 d0 f7 ee 0c 20 ee 0f 20 ca d0 ee 4c 00 10 20 0c 10 20 52 10 20 39 13 4c b9 10 ad 30 bf 8d 41 10 ae 80 02 f0 24 a0 00 bd 80 02 29 7f c9 2f f0 04 c8 ca d0 f3 db dc 00 f0 11 8c 42 10 ae 80 02 bd 80 02 99 42 10 ca 88 d0 f6 60 a9 00 8d 42 10 60 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 d8 2c 82 db dc a9 16 8d f2 03 a9 12 8d f3 03 49 a5 8d f4 03 a9 95 20 ed fd 8d 0c db dc 8d 0e db dc 8d 00 db dc 20 84 fe 20 2f fb 20 93 fe 20 89 fe a2 17 a9 01 9d 58 bf a9 00 ca d0 f8 a9 cf 8d 58 bf ad 98 bf 29 88 d0 05 a9 df 8d 58 12 60 02 00 00 1c 03 80 02 00 1c 00 04 00 00 20 00 9f 00 00 04 00 00 20 00 02 00 00 01 00 ad 42 10 d0 03 4c 16 12 ad 41 10 8d 9e 10 20 00 bf c5 9d 10 90 03 4c e6 11 a9 2f 8d 81 02 ad 00 1c 29 0f 8d 80 02 a2 00 bd 01 1c 9d 82 02 e8 ec 80 02 d0 f4 e8 8e 80 02 20 00 bf c8 a1 10 90 03 4c e6 11 ad a6 10 8d b0 10 8d b8 10 20 00 bf ca af 10 90 09 20 00 bf cc b7 10 4c e6 11 ad 23 20 8d 6c 11 ad 24 20 8d 78 11 a9 01 85 a7 a9 2b 85 a5 a9 20 85 a6 a0 10 b1 a5 c9 ff d0 32 a0 00 b1 a5 29 30 f0 2a b1 a5 29 0f 85 a8 a8 ae 24 12 b1 a5 dd 24 12 d0 19 88 ca d0 f5 ac 42 10 c4 a8 d0 38 b1 a5 d9 42 10 d0 31 88 d0 f6 38 6e 2c 12 a5 a5 18 69 27 85 a5 90 02 e6 a6 e6 a7 a5 a7 c9 0d 90 b3 20 00 bf ca af 10 b0 36 a9 00 85 a7 a9 04 85 a5 a9 20 85 a6 4c 2e 11 2c 2c 12 10 d1 20 00 bf cc b7 10 ae 80 02 e8 a9 2f 9d 80 02 a0 00 c8 e8 b1 a5 9d 80 02 c4 a8 90 f5 8e 80 02 4c c2 11 20 00 bf cc b7 10 4c 16 12 20 00 bf c8 a1 10 b0 1c ad a6 10 8d a8 10 8d b8 10 20 00 bf ca a7 10 08 20 00 bf cc b7 10 28 c0
 FujiNet -> AppleWin  .  .  .  L  .     .  .  .  .  .  .  .  .  .     .  .  .  .  .  .  .  .     .  .     .  .  .  L  .  .     .  .     R  .     9  .  L  .  .  .  0  .  .  A  .  .  .  .  .  $  .  .  .  .  .  )  .  .  /  .  .  .  .  .  .  .  .  .  .  .  .  B  .  .  .  .  .  .  .  .  B  .  .  .  .  .  `  .  .  .  B  .  `  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  .  .  .  .  .  .  .  .  I  .  .  .  .  .  .     .  .  .  .  .  .  .  .  .  .  .  .  .  .     .  .     /  .     .  .     .  .  .  .  .  .  .  X  .  .  .  .  .  .  .  .  .  X  .  .  .  .  )  .  .  .  .  .  .  X  .  `  .  .  .  .  .  .  .  .  .  .  .  .  .     .  .  .  .  .  .  .     .  .  .  .  .  .  .  B  .  .  .  L  .  .  .  A  .  .  .  .     .  .  .  .  .  .  .  L  .  .  .  /  .  .  .  .  .  .  )  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .     .  .  .  .  .  .  .  L  .  .  .  .  .  .  .  .  .  .  .     .  .  .  .  .  .  .     .  .  .  .  .  L  .  .  .  #     .  l  .  .  $     .  x  .  .  .  .  .  .  +  .  .  .     .  .  .  .  .  .  .  .  .  2  .  .  .  .  )  0  .  *  .  .  )  .  .  .  .  .  $  .  .  .  .  $  .  .  .  .  .  .  .  .  B  .  .  .  .  8  .  .  .  B  .  .  1  .  .  .  8  n  ,  .  .  .  .  i  '  .  .  .  .  .  .  .  .  .  .  .  .  .  .     .  .  .  .  .  .  6  .  .  .  .  .  .  .  .  .     .  .  L  .  .  ,  ,  .  .  .     .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  L  .  .     .  .  .  .  .  L  .  .     .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .     .  .  .  .  .  .     .  .  .  .  .  (  .
AppleWin ->  FujiNet c0 0d 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 0d 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 0e 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 0e 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 0f 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 0f 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 10 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 10 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 11 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 11 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 12 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 12 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 13 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 13 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 14 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 14 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 15 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 15 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 16 01 01 00 02 2b 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  +  .  .  .
 FujiNet -> AppleWin c0 16 00 b0 03 4c 00 20 48 20 33 12 8d 8d aa a0 a0 c4 e9 f3 eb a0 c5 f2 f2 ef f2 a0 a4 00 68 20 da fd 20 33 12 a0 a0 aa 8d 00 2c 10 db dc ad 00 db dc 10 fb 2c 10 db dc 4c 16 12 20 00 bf 65 1d 12 00 04 00 00 00 00 00 00 07 2e 53 59 53 54 45 4d 00 20 8e fd 20 8e fd 68 85 a5 68 85 a6 d0 0a c9 e1 90 03 2d 58 12 20 ed fd e6 a5 d0 02 e6 a6 a0 00 b1 a5 d0 ea a5 a6 48 a5 a5 48 60 ff a2 b0 c9 0a 90 07 e9 0a e8 c9 0a b0 f9 48 e0 b0 f0 04 8a 20 ed fd 68 09 b0 20 ed fd 60 ad 91 bf 6a 48 ad 90 bf 48 2a 2a 2a 2a 29 0f 20 59 12 a9 af 20 ed fd 68 29 1f 20 59 12 a9 af 20 ed fd 68 20 59 12 60 a9 00 85 a5 86 a6 a0 01 b1 a5 c9 20 d0 1c a0 03 b1 a5 c9 00 d0 14 a0 05 b1 a5 c9 03 d0 0c a0 07 b1 a5 c9 00 d0 04 a6 a6 18 60 a6 a6 ca e0 c1 b0 d3 a2 00 38 60 a9 00 85 a5 86 a6 a0 ff b1 a5 18 69 03 8d 15 13 8e 16 13 60 a9 00 8d 1c 13 8d 1f 13 20 14 13 b0 04 ae 20 13 60 a2 00 60 8e 1c 13 a9 03 8d 1f 13 20 14 13 b0 07 ad 35 13 ae 1c 13 60 a9 ff ae 1c 13 60 20 00 00 00 1b 13 60 03 00 20 13 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 ad 98 bf 29 01 f0 13 60 08 78 20 0d c5 00 0d 00 8d ff cf 28 60 03 00 90 bf 50 a2 c7 20 9d 12 b0 31 20 d2 12 20 e6 12 e0 00 f0 0a 20 fa 12 c9 13 f0 0e ca d0 f6 ae 15 13 ca e0 db dc d0 df 4c 8b 13 8e 4f 13 ad 15 13 8d 44 13 ad 16 13 8d 45 13 4c ab 13 20 2d 12 c6 f5 ea e9 ee e5 f4 a0 c3 ec ef e3 eb a0 ad a0 ce ef f4 a0 c6 ef f5 ee e4 ae 00 38 60 ad 07 bf 85 a5 ad 08 bf 85 a6 18 a5 a5 6d 47 13 8d 47 13 a5 a6 6d 48 13 8d 48 13 ad 8b db dc ad 8b db dc a0 11 b9 41 13 91 a5 88 10 f8 ad 98 bf 09 01 8d 98 bf a9 4c 8d c0
 FujiNet -> AppleWin  .  .  .  .  .  L  .     H     3  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  h     .  .     3  .  .  .  .  .  .  ,  .  .  .  .  .  .  .  .  .  ,  .  .  .  L  .  .     .  .  e  .  .  .  .  .  .  .  .  .  .  .  .  S  Y  S  T  E  M  .     .  .     .  .  h  .  .  h  .  .  .  .  .  .  .  .  -  X  .     .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  H  .  .  H  `  .  .  .  .  .  .  .  .  .  .  .  .  .  .  H  .  .  .  .  .     .  .  h  .  .     .  .  `  .  .  .  j  H  .  .  .  H  *  *  *  *  )  .     Y  .  .  .     .  .  h  )  .     Y  .  .  .     .  .  h     Y  .  `  .  .  .  .  .  .  .  .  .  .  .     .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  `  .  .  .  .  .  .  .  .  .  8  `  .  .  .  .  .  .  .  .  .  .  .  i  .  .  .  .  .  .  .  `  .  .  .  .  .  .  .  .     .  .  .  .  .     .  `  .  .  `  .  .  .  .  .  .  .  .     .  .  .  .  .  5  .  .  .  .  `  .  .  .  .  .  `     .  .  .  .  .  `  .  .     .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  )  .  .  .  `  .  x     .  .  .  .  .  .  .  .  (  `  .  .  .  .  P  .  .     .  .  .  1     .  .     .  .  .  .  .  .     .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  L  .  .  .  O  .  .  .  .  .  D  .  .  .  .  .  E  .  L  .  .     -  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  8  `  .  .  .  .  .  .  .  .  .  .  .  .  .  m  G  .  .  G  .  .  .  m  H  .  .  H  .  .  .  .  .  .  .  .  .  .  .  .  A  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  L  .  .
AppleWin ->  FujiNet c0 17 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 17 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 18 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 18 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 19 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 19 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 1a 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 1a 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 1b 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 1b 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 1c 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 1c 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 1d 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 1d 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 1e 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 1e 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 1f 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 1f 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 20 01 01 00 02 2c 00 00 c0
AppleWin ->  FujiNet  .     .  .  .  .  ,  .  .  .
 FujiNet -> AppleWin c0 20 00 06 bf 20 06 bf ad 82 db dc 20 2d 12 c6 f5 ea e9 ee e5 f4 a0 c3 ec ef e3 eb a0 ad a0 00 20 76 12 18 60 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .     .  .  .     .  .  .  .  .  .     -  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .     v  .  .  `  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 21 00 09 03 c0
AppleWin ->  FujiNet  .  !  .  .  .  .
 FujiNet -> AppleWin c0 21 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  !  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 22 00 08 03 c0
AppleWin ->  FujiNet  .  "  .  .  .  .
 FujiNet -> AppleWin c0 22 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  "  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 23 00 07 03 c0
AppleWin ->  FujiNet  .  #  .  .  .  .
 FujiNet -> AppleWin c0 23 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  #  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 24 00 06 03 c0
AppleWin ->  FujiNet  .  $  .  .  .  .
 FujiNet -> AppleWin c0 24 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  $  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 25 00 06 50 c0
AppleWin ->  FujiNet  .  %  .  .  P  .
 FujiNet -> AppleWin c0 25 00 25 31 16 0e c0
 FujiNet -> AppleWin  .  %  .  %  1  .  .  .
AppleWin ->  FujiNet c0 26 00 01 03 c0
AppleWin ->  FujiNet  .  &  .  .  .  .
 FujiNet -> AppleWin c0 26 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  &  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 27 00 02 03 c0
AppleWin ->  FujiNet  .  '  .  .  .  .
 FujiNet -> AppleWin c0 27 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  '  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 28 00 03 03 c0
AppleWin ->  FujiNet  .  (  .  .  .  .
 FujiNet -> AppleWin c0 28 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  (  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 29 00 04 03 c0
AppleWin ->  FujiNet  .  )  .  .  .  .
 FujiNet -> AppleWin c0 29 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  )  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 2a 00 05 03 c0
AppleWin ->  FujiNet  .  *  .  .  .  .
 FujiNet -> AppleWin c0 2a 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  *  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 2b 00 06 03 c0
AppleWin ->  FujiNet  .  +  .  .  .  .
 FujiNet -> AppleWin c0 2b 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  +  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 2c 00 07 03 c0
AppleWin ->  FujiNet  .  ,  .  .  .  .
 FujiNet -> AppleWin c0 2c 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  ,  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 2d 00 08 03 c0
AppleWin ->  FujiNet  .  -  .  .  .  .
 FujiNet -> AppleWin c0 2d 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  -  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 2e 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 2e 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 2f 01 01 00 02 02 00 00 c0
AppleWin ->  FujiNet  .  /  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 2f 00 00 00 03 00 fa 49 53 53 54 52 41 43 4b 45 52 00 00 00 00 00 00 00 d0 2c 02 12 00 00 d0 2c 02 12 00 00 e3 27 0d 04 00 06 00 18 01 26 50 52 4f 44 4f 53 00 00 00 00 00 00 00 00 00 ff 07 00 22 00 e8 42 00 2d 24 09 09 00 00 21 00 00 32 24 00 07 02 00 2f 46 4e 2e 43 4c 4f 43 4b 2e 53 59 53 54 45 4d ff 2a 00 04 00 21 04 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 1c 43 4c 4f 43 4b 2e 53 59 53 54 45 4d 00 00 00 ff 2d 00 01 00 cb 01 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 25 43 4c 4f 43 4b 00 00 00 00 00 00 00 00 00 00 06 2f 00 0e 00 96 18 00 78 2e 37 17 00 00 c3 00 40 78 2e 37 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  /  .  .  .  .  .  .  I  S  S  T  R  A  C  K  E  R  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  ,  .  .  .  .  .  '  .  .  .  .  .  .  .  &  P  R  O  D  O  S  .  .  .  .  .  .  .  .  .  .  .  .  "  .  .  B  .  -  $  .  .  .  .  !  .  .  2  $  .  .  .  .  /  F  N  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  *  .  .  .  !  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  .  .  .  -  .  .  .  .  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  %  C  L  O  C  K  .  .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  x  .  7  .  .  .  .  .  @  x  .  7  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 30 00 01 03 c0
AppleWin ->  FujiNet  .  0  .  .  .  .
 FujiNet -> AppleWin c0 30 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  0  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 31 00 02 03 c0
AppleWin ->  FujiNet  .  1  .  .  .  .
 FujiNet -> AppleWin c0 31 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  1  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 32 00 03 03 c0
AppleWin ->  FujiNet  .  2  .  .  .  .
 FujiNet -> AppleWin c0 32 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  2  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 33 00 04 03 c0
AppleWin ->  FujiNet  .  3  .  .  .  .
 FujiNet -> AppleWin c0 33 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  3  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 34 00 05 03 c0
AppleWin ->  FujiNet  .  4  .  .  .  .
 FujiNet -> AppleWin c0 34 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  4  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 35 00 06 03 c0
AppleWin ->  FujiNet  .  5  .  .  .  .
 FujiNet -> AppleWin c0 35 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  5  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 36 00 07 03 c0
AppleWin ->  FujiNet  .  6  .  .  .  .
 FujiNet -> AppleWin c0 36 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  6  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 37 00 08 03 c0
AppleWin ->  FujiNet  .  7  .  .  .  .
 FujiNet -> AppleWin c0 37 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  7  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 38 00 09 03 c0
AppleWin ->  FujiNet  .  8  .  .  .  .
 FujiNet -> AppleWin c0 38 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  8  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 39 01 01 00 02 02 00 00 c0
AppleWin ->  FujiNet  .  9  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 39 00 00 00 03 00 fa 49 53 53 54 52 41 43 4b 45 52 00 00 00 00 00 00 00 d0 2c 02 12 00 00 d0 2c 02 12 00 00 e3 27 0d 04 00 06 00 18 01 26 50 52 4f 44 4f 53 00 00 00 00 00 00 00 00 00 ff 07 00 22 00 e8 42 00 2d 24 09 09 00 00 21 00 00 32 24 00 07 02 00 2f 46 4e 2e 43 4c 4f 43 4b 2e 53 59 53 54 45 4d ff 2a 00 04 00 21 04 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 1c 43 4c 4f 43 4b 2e 53 59 53 54 45 4d 00 00 00 ff 2d 00 01 00 cb 01 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 25 43 4c 4f 43 4b 00 00 00 00 00 00 00 00 00 00 06 2f 00 0e 00 96 18 00 78 2e 37 17 00 00 c3 00 40 78 2e 37 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  9  .  .  .  .  .  .  I  S  S  T  R  A  C  K  E  R  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  ,  .  .  .  .  .  '  .  .  .  .  .  .  .  &  P  R  O  D  O  S  .  .  .  .  .  .  .  .  .  .  .  .  "  .  .  B  .  -  $  .  .  .  .  !  .  .  2  $  .  .  .  .  /  F  N  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  *  .  .  .  !  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  .  .  .  -  .  .  .  .  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  %  C  L  O  C  K  .  .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  x  .  7  .  .  .  .  .  @  x  .  7  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 3a 00 01 03 c0
AppleWin ->  FujiNet  .  :  .  .  .  .
 FujiNet -> AppleWin c0 3a 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  :  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 3b 00 02 03 c0
AppleWin ->  FujiNet  .  ;  .  .  .  .
 FujiNet -> AppleWin c0 3b 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  ;  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 3c 00 03 03 c0
AppleWin ->  FujiNet  .  <  .  .  .  .
 FujiNet -> AppleWin c0 3c 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  <  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 3d 00 04 03 c0
AppleWin ->  FujiNet  .  =  .  .  .  .
 FujiNet -> AppleWin c0 3d 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  =  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 3e 00 05 03 c0
AppleWin ->  FujiNet  .  >  .  .  .  .
 FujiNet -> AppleWin c0 3e 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  >  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 3f 00 06 03 c0
AppleWin ->  FujiNet  .  ?  .  .  .  .
 FujiNet -> AppleWin c0 3f 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  ?  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 40 00 07 03 c0
AppleWin ->  FujiNet  .  @  .  .  .  .
 FujiNet -> AppleWin c0 40 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  @  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 41 00 08 03 c0
AppleWin ->  FujiNet  .  A  .  .  .  .
 FujiNet -> AppleWin c0 41 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  A  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 42 00 09 03 c0
AppleWin ->  FujiNet  .  B  .  .  .  .
 FujiNet -> AppleWin c0 42 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  B  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 43 01 01 00 02 02 00 00 c0
AppleWin ->  FujiNet  .  C  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 43 00 00 00 03 00 fa 49 53 53 54 52 41 43 4b 45 52 00 00 00 00 00 00 00 d0 2c 02 12 00 00 d0 2c 02 12 00 00 e3 27 0d 04 00 06 00 18 01 26 50 52 4f 44 4f 53 00 00 00 00 00 00 00 00 00 ff 07 00 22 00 e8 42 00 2d 24 09 09 00 00 21 00 00 32 24 00 07 02 00 2f 46 4e 2e 43 4c 4f 43 4b 2e 53 59 53 54 45 4d ff 2a 00 04 00 21 04 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 1c 43 4c 4f 43 4b 2e 53 59 53 54 45 4d 00 00 00 ff 2d 00 01 00 cb 01 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 25 43 4c 4f 43 4b 00 00 00 00 00 00 00 00 00 00 06 2f 00 0e 00 96 18 00 78 2e 37 17 00 00 c3 00 40 78 2e 37 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  C  .  .  .  .  .  .  I  S  S  T  R  A  C  K  E  R  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  ,  .  .  .  .  .  '  .  .  .  .  .  .  .  &  P  R  O  D  O  S  .  .  .  .  .  .  .  .  .  .  .  .  "  .  .  B  .  -  $  .  .  .  .  !  .  .  2  $  .  .  .  .  /  F  N  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  *  .  .  .  !  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  .  .  .  -  .  .  .  .  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  %  C  L  O  C  K  .  .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  x  .  7  .  .  .  .  .  @  x  .  7  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 44 00 01 03 c0
AppleWin ->  FujiNet  .  D  .  .  .  .
 FujiNet -> AppleWin c0 44 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  D  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 45 00 02 03 c0
AppleWin ->  FujiNet  .  E  .  .  .  .
 FujiNet -> AppleWin c0 45 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  E  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 46 00 03 03 c0
AppleWin ->  FujiNet  .  F  .  .  .  .
 FujiNet -> AppleWin c0 46 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  F  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 47 00 04 03 c0
AppleWin ->  FujiNet  .  G  .  .  .  .
 FujiNet -> AppleWin c0 47 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  G  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 48 00 05 03 c0
AppleWin ->  FujiNet  .  H  .  .  .  .
 FujiNet -> AppleWin c0 48 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  H  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 49 00 06 03 c0
AppleWin ->  FujiNet  .  I  .  .  .  .
 FujiNet -> AppleWin c0 49 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  I  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 4a 00 07 03 c0
AppleWin ->  FujiNet  .  J  .  .  .  .
 FujiNet -> AppleWin c0 4a 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  J  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 4b 00 08 03 c0
AppleWin ->  FujiNet  .  K  .  .  .  .
 FujiNet -> AppleWin c0 4b 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  K  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 4c 00 09 03 c0
AppleWin ->  FujiNet  .  L  .  .  .  .
 FujiNet -> AppleWin c0 4c 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  L  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 4d 01 01 00 02 03 00 00 c0
AppleWin ->  FujiNet  .  M  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 4d 00 02 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  M  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 4e 00 06 50 c0
AppleWin ->  FujiNet  .  N  .  .  P  .
 FujiNet -> AppleWin c0 4e 00 25 31 16 0e c0
 FujiNet -> AppleWin  .  N  .  %  1  .  .  .
AppleWin ->  FujiNet c0 4f 00 01 03 c0
AppleWin ->  FujiNet  .  O  .  .  .  .
 FujiNet -> AppleWin c0 4f 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  O  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 50 00 02 03 c0
AppleWin ->  FujiNet  .  P  .  .  .  .
 FujiNet -> AppleWin c0 50 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  P  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 51 00 03 03 c0
AppleWin ->  FujiNet  .  Q  .  .  .  .
 FujiNet -> AppleWin c0 51 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  Q  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 52 00 04 03 c0
AppleWin ->  FujiNet  .  R  .  .  .  .
 FujiNet -> AppleWin c0 52 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  R  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 53 00 05 03 c0
AppleWin ->  FujiNet  .  S  .  .  .  .
 FujiNet -> AppleWin c0 53 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  S  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 54 00 06 03 c0
AppleWin ->  FujiNet  .  T  .  .  .  .
 FujiNet -> AppleWin c0 54 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  T  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 55 00 07 03 c0
AppleWin ->  FujiNet  .  U  .  .  .  .
 FujiNet -> AppleWin c0 55 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  U  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 56 00 08 03 c0
AppleWin ->  FujiNet  .  V  .  .  .  .
 FujiNet -> AppleWin c0 56 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  V  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 57 00 09 03 c0
AppleWin ->  FujiNet  .  W  .  .  .  .
 FujiNet -> AppleWin c0 57 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  W  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 58 01 01 00 02 02 00 00 c0
AppleWin ->  FujiNet  .  X  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 58 00 00 00 03 00 fa 49 53 53 54 52 41 43 4b 45 52 00 00 00 00 00 00 00 d0 2c 02 12 00 00 d0 2c 02 12 00 00 e3 27 0d 04 00 06 00 18 01 26 50 52 4f 44 4f 53 00 00 00 00 00 00 00 00 00 ff 07 00 22 00 e8 42 00 2d 24 09 09 00 00 21 00 00 32 24 00 07 02 00 2f 46 4e 2e 43 4c 4f 43 4b 2e 53 59 53 54 45 4d ff 2a 00 04 00 21 04 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 1c 43 4c 4f 43 4b 2e 53 59 53 54 45 4d 00 00 00 ff 2d 00 01 00 cb 01 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 25 43 4c 4f 43 4b 00 00 00 00 00 00 00 00 00 00 06 2f 00 0e 00 96 18 00 78 2e 37 17 00 00 c3 00 40 78 2e 37 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  X  .  .  .  .  .  .  I  S  S  T  R  A  C  K  E  R  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  ,  .  .  .  .  .  '  .  .  .  .  .  .  .  &  P  R  O  D  O  S  .  .  .  .  .  .  .  .  .  .  .  .  "  .  .  B  .  -  $  .  .  .  .  !  .  .  2  $  .  .  .  .  /  F  N  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  *  .  .  .  !  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  .  .  .  -  .  .  .  .  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  %  C  L  O  C  K  .  .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  x  .  7  .  .  .  .  .  @  x  .  7  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 59 00 01 03 c0
AppleWin ->  FujiNet  .  Y  .  .  .  .
 FujiNet -> AppleWin c0 59 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  Y  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 5a 00 02 03 c0
AppleWin ->  FujiNet  .  Z  .  .  .  .
 FujiNet -> AppleWin c0 5a 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  Z  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 5b 00 03 03 c0
AppleWin ->  FujiNet  .  [  .  .  .  .
 FujiNet -> AppleWin c0 5b 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  [  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 5c 00 04 03 c0
AppleWin ->  FujiNet  .  \  .  .  .  .
 FujiNet -> AppleWin c0 5c 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  \  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 5d 00 05 03 c0
AppleWin ->  FujiNet  .  ]  .  .  .  .
 FujiNet -> AppleWin c0 5d 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  ]  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 5e 00 06 03 c0
AppleWin ->  FujiNet  .  ^  .  .  .  .
 FujiNet -> AppleWin c0 5e 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  ^  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 5f 00 07 03 c0
AppleWin ->  FujiNet  .  _  .  .  .  .
 FujiNet -> AppleWin c0 5f 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  _  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 60 00 08 03 c0
AppleWin ->  FujiNet  .  `  .  .  .  .
 FujiNet -> AppleWin c0 60 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  `  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 61 00 09 03 c0
AppleWin ->  FujiNet  .  a  .  .  .  .
 FujiNet -> AppleWin c0 61 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  a  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 62 01 01 00 02 2d 00 00 c0
AppleWin ->  FujiNet  .  b  .  .  .  .  -  .  .  .
 FujiNet -> AppleWin c0 62 00 4c 85 20 ee ee 7f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a2 ff 9a a2 ad bd 1d 21 9d ff 02 ca d0 f7 ad 80 02 38 e9 07 8d 80 02 aa a9 00 9d 81 02 ae 06 20 a9 00 f0 03 bd 07 20 9d 00 01 ca 10 f7 a9 0d a2 21 20 22 03 a9 81 a2 02 20 22 03 a9 17 a2 21 20 22 03 20 00 bf c4 f5 20 90 03 4c 42 03 20 00 bf c8 07 21 90 03 4c 42 03 ad 0c 21 8d 6c 03 8d 74 03 ad fa 20 ae fb 20 8d 6d 03 8e 6e 03 4c 00 03 0a 80 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 80 02 00 bb 00 0d 4c 6f 61 64 69 6e 67 20 00 20 2e 2e 2e 0d 0d 00 20 00 bf ca 6b 03 b0 3a 20 00 bf cc 73 03 b0 32 a2 00 a9 b2 d0 04 e8 bd ff 00 9d 00 02 d0 f7 6c 6d 03 85 3c 86 3d ae b3 fb a0 00 b1 3c f0 12 e0 06 f0 06 c9 60 90 02 29 5f 09 80 20 ed fd c8 d0 ea 60 c9 46 d0 09 a9 7c a2 03 20 22 03 f0 0c 48 a9 8f a2 03 20 22 03 68 20 da fd a9 9b a2 03 20 22 03 20 0c fd 20 00 bf 65 75 03 04 00 00 00 ff ff 00 00 01 00 04 00 00 00 00 00 00 2e 2e 2e 20 46 69 6c 65 20 4e 6f 74 20 46 6f 75 6e 64 00 2e 2e 2e 20 45 72 72 6f 72 20 24 00 20 2d 20 50 72 65 73 73 20 41 6e 79 20 4b 65 79 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  b  .  L  .     .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  !  .  .  .  .  .  .  .  .  .  8  .  .  .  .  .  .  .  .  .  .  .  .  .     .  .  .  .  .  .     .  .  .  .  .  .  .  .  .  !     "  .  .  .  .  .     "  .  .  .  .  !     "  .     .  .  .  .     .  .  L  B  .     .  .  .  .  !  .  .  L  B  .  .  .  !  .  l  .  .  t  .  .  .     .  .     .  m  .  .  n  .  L  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  L  o  a  d  i  n  g     .     .  .  .  .  .  .     .  .  .  k  .  .  :     .  .  .  s  .  .  2  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  l  m  .  .  <  .  =  .  .  .  .  .  .  <  .  .  .  .  .  .  .  `  .  .  )  _  .  .     .  .  .  .  .  `  .  F  .  .  .  .  .  .     "  .  .  .  H  .  .  .  .     "  .  h     .  .  .  .  .  .     "  .     .  .     .  .  e  u  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .     F  i  l  e     N  o  t     F  o  u  n  d  .  .  .  .     E  r  r  o  r     $  .     -     P  r  e  s  s     A  n  y     K  e  y     .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 63 00 06 50 c0
AppleWin ->  FujiNet  .  c  .  .  P  .
 FujiNet -> AppleWin c0 63 00 25 31 16 0e c0
 FujiNet -> AppleWin  .  c  .  %  1  .  .  .
AppleWin ->  FujiNet c0 64 00 01 03 c0
AppleWin ->  FujiNet  .  d  .  .  .  .
 FujiNet -> AppleWin c0 64 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  d  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 65 00 02 03 c0
AppleWin ->  FujiNet  .  e  .  .  .  .
 FujiNet -> AppleWin c0 65 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  e  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 66 00 03 03 c0
AppleWin ->  FujiNet  .  f  .  .  .  .
 FujiNet -> AppleWin c0 66 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  f  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 67 00 04 03 c0
AppleWin ->  FujiNet  .  g  .  .  .  .
 FujiNet -> AppleWin c0 67 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  g  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 68 00 05 03 c0
AppleWin ->  FujiNet  .  h  .  .  .  .
 FujiNet -> AppleWin c0 68 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  h  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 69 00 06 03 c0
AppleWin ->  FujiNet  .  i  .  .  .  .
 FujiNet -> AppleWin c0 69 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  i  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 6a 00 07 03 c0
AppleWin ->  FujiNet  .  j  .  .  .  .
 FujiNet -> AppleWin c0 6a 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  j  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 6b 00 08 03 c0
AppleWin ->  FujiNet  .  k  .  .  .  .
 FujiNet -> AppleWin c0 6b 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  k  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 6c 00 09 03 c0
AppleWin ->  FujiNet  .  l  .  .  .  .
 FujiNet -> AppleWin c0 6c 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  l  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 6d 01 01 00 02 02 00 00 c0
AppleWin ->  FujiNet  .  m  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 6d 00 00 00 03 00 fa 49 53 53 54 52 41 43 4b 45 52 00 00 00 00 00 00 00 d0 2c 02 12 00 00 d0 2c 02 12 00 00 e3 27 0d 04 00 06 00 18 01 26 50 52 4f 44 4f 53 00 00 00 00 00 00 00 00 00 ff 07 00 22 00 e8 42 00 2d 24 09 09 00 00 21 00 00 32 24 00 07 02 00 2f 46 4e 2e 43 4c 4f 43 4b 2e 53 59 53 54 45 4d ff 2a 00 04 00 21 04 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 1c 43 4c 4f 43 4b 2e 53 59 53 54 45 4d 00 00 00 ff 2d 00 01 00 cb 01 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 25 43 4c 4f 43 4b 00 00 00 00 00 00 00 00 00 00 06 2f 00 0e 00 96 18 00 78 2e 37 17 00 00 c3 00 40 78 2e 37 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  m  .  .  .  .  .  .  I  S  S  T  R  A  C  K  E  R  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  ,  .  .  .  .  .  '  .  .  .  .  .  .  .  &  P  R  O  D  O  S  .  .  .  .  .  .  .  .  .  .  .  .  "  .  .  B  .  -  $  .  .  .  .  !  .  .  2  $  .  .  .  .  /  F  N  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  *  .  .  .  !  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  .  .  .  -  .  .  .  .  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  %  C  L  O  C  K  .  .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  x  .  7  .  .  .  .  .  @  x  .  7  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 6e 00 01 03 c0
AppleWin ->  FujiNet  .  n  .  .  .  .
 FujiNet -> AppleWin c0 6e 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  n  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 6f 00 02 03 c0
AppleWin ->  FujiNet  .  o  .  .  .  .
 FujiNet -> AppleWin c0 6f 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  o  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 70 00 03 03 c0
AppleWin ->  FujiNet  .  p  .  .  .  .
 FujiNet -> AppleWin c0 70 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  p  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 71 00 04 03 c0
AppleWin ->  FujiNet  .  q  .  .  .  .
 FujiNet -> AppleWin c0 71 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  q  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 72 00 05 03 c0
AppleWin ->  FujiNet  .  r  .  .  .  .
 FujiNet -> AppleWin c0 72 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  r  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 73 00 06 03 c0
AppleWin ->  FujiNet  .  s  .  .  .  .
 FujiNet -> AppleWin c0 73 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  s  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 74 00 07 03 c0
AppleWin ->  FujiNet  .  t  .  .  .  .
 FujiNet -> AppleWin c0 74 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  t  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 75 00 08 03 c0
AppleWin ->  FujiNet  .  u  .  .  .  .
 FujiNet -> AppleWin c0 75 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  u  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 76 00 09 03 c0
AppleWin ->  FujiNet  .  v  .  .  .  .
 FujiNet -> AppleWin c0 76 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  v  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 77 01 01 00 02 02 00 00 c0
AppleWin ->  FujiNet  .  w  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 77 00 00 00 03 00 fa 49 53 53 54 52 41 43 4b 45 52 00 00 00 00 00 00 00 d0 2c 02 12 00 00 d0 2c 02 12 00 00 e3 27 0d 04 00 06 00 18 01 26 50 52 4f 44 4f 53 00 00 00 00 00 00 00 00 00 ff 07 00 22 00 e8 42 00 2d 24 09 09 00 00 21 00 00 32 24 00 07 02 00 2f 46 4e 2e 43 4c 4f 43 4b 2e 53 59 53 54 45 4d ff 2a 00 04 00 21 04 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 1c 43 4c 4f 43 4b 2e 53 59 53 54 45 4d 00 00 00 ff 2d 00 01 00 cb 01 00 78 2e 37 17 00 00 c3 00 20 78 2e 37 17 02 00 25 43 4c 4f 43 4b 00 00 00 00 00 00 00 00 00 00 06 2f 00 0e 00 96 18 00 78 2e 37 17 00 00 c3 00 40 78 2e 37 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  w  .  .  .  .  .  .  I  S  S  T  R  A  C  K  E  R  .  .  .  .  .  .  .  .  ,  .  .  .  .  .  ,  .  .  .  .  .  '  .  .  .  .  .  .  .  &  P  R  O  D  O  S  .  .  .  .  .  .  .  .  .  .  .  .  "  .  .  B  .  -  $  .  .  .  .  !  .  .  2  $  .  .  .  .  /  F  N  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  *  .  .  .  !  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  .  C  L  O  C  K  .  S  Y  S  T  E  M  .  .  .  .  -  .  .  .  .  .  .  x  .  7  .  .  .  .  .     x  .  7  .  .  .  %  C  L  O  C  K  .  .  .  .  .  .  .  .  .  .  .  /  .  .  .  .  .  .  x  .  7  .  .  .  .  .  @  x  .  7  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 78 00 01 03 c0
AppleWin ->  FujiNet  .  x  .  .  .  .
 FujiNet -> AppleWin c0 78 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  x  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 79 00 02 03 c0
AppleWin ->  FujiNet  .  y  .  .  .  .
 FujiNet -> AppleWin c0 79 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  y  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 7a 00 03 03 c0
AppleWin ->  FujiNet  .  z  .  .  .  .
 FujiNet -> AppleWin c0 7a 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  z  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 7b 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 7b 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 7c 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 7c 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 7d 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 7d 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 7e 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 7e 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 7f 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 7f 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 80 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 80 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 81 01 01 00 02 2f 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  /  .  .  .
 FujiNet -> AppleWin c0 81 00 2e 30 31 32 33 34 35 36 37 38 39 3a 3b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  0  1  2  3  4  5  6  7  8  9  :  ;  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 82 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 82 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 83 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 83 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 84 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 84 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 85 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 85 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 86 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 86 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 87 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 87 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 88 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 88 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 89 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 89 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 8a 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 8a 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 8b 01 01 00 02 2e 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 8b 00 a2 ff 9a 20 14 58 20 a4 54 20 11 4e a2 19 a9 40 20 ec 4e 2c 82 db dc 20 50 4e a2 02 bd f0 57 9d f2 03 ca 10 f7 a2 19 bd d6 57 95 80 ca 10 f8 a2 ff 9a 4c 7e 57 2c 82 db dc 20 ed fd 2c 80 db dc 60 2c 82 db dc 20 58 fc 2c 80 db dc 60 2c 82 db dc 20 24 fc 2c 80 db dc 60 20 3d 50 20 00 52 a2 00 bd 2a 57 f0 08 e8 e0 08 90 f6 a9 02 60 a9 ff 9d 2a 57 8a 0a 0a 18 69 08 a0 01 91 88 88 98 91 88 60 8a 38 e9 08 4a 4a aa a9 00 9d 2a 57 60 20 3e 40 20 58 47 20 c9 45 8d f3 57 a2 00 ad f3 57 20 4a 52 a2 00 a9 54 20 86 41 a9 19 a2 55 20 60 52 a2 00 ad f6 57 20 60 52 a2 00 ad f7 57 20 60 52 a2 00 ad f8 57 20 60 52 a2 00 ad f9 57 20 60 52 a2 00 ad fa 57 20 60 52 a2 00 ad fb 57 20 60 52 a2 00 ad fc 57 20 60 52 a0 10 20 0e 52 a9 82 8d ef 40 20 00 bf ea ea ea a2 bf a9 90 8d f4 57 8e f5 57 a9 c7 a2 54 20 60 52 ad f4 57 ae f5 57 20 06 50 a0 00 20 55 50 20 e1 4d 20 60 52 ad f4 57 ae f5 57 20 06 50 a0 00 20 55 50 a2 00 29 01 20 d3 4d 20 60 52 ad f4 57 ae f5 57 a0 00 20 55 50 20 eb 4d 20 e1 4d 20 ab 4d 20 60 52 ad f4 57 ae f5 57 a0 00 20 55 50 a2 00 29 1f 20 60 52 ad f4 57 ae f5 57 20 14 50 a0 00 20 55 50 20 60 52 ad f4 57 ae f5 57 20 0d 50 a0 00 20 55 50 20 60 52 a0 0c 20 0e 52 4c 82 41 4c 82 41 60 20 4a 52 a2 00 a9 00 8d f9 5b a2 00 a9 03 8d fa 5b a0 01 a2 00 b1 80 8d fb 5b a9 f6 a2 57 a2 00 a2 00 8d fc 5b a9 f6 a2 57 8a a2 00 a2 00 a2 00 a2 00 8d fd 5b a0 00 a2 00 b1 80 8d fe 5b a9 20 8d 03 42 ad 09 5c 8d e6 41 8d ed 41 ad 0a 5c 8d e7 41 8d ee 41 a9 bd 8d e5 41 8d ec 41 a2 00 ea ea ea 8d 04 42 e8 ea ea ea 8d 05 42 a9 00 8d 06 42 ad 04 5c 8d 07 42 ad 05 5c c0
 FujiNet -> AppleWin  .  .  .  .  .  .     .  X     .  T     .  N  .  .  .  @     .  N  ,  .  .  .     P  N  .  .  .  .  W  .  .  .  .  .  .  .  .  .  .  W  .  .  .  .  .  .  .  .  L  .  W  ,  .  .  .     .  .  ,  .  .  .  `  ,  .  .  .     X  .  ,  .  .  .  `  ,  .  .  .     $  .  ,  .  .  .  `     =  P     .  R  .  .  .  *  W  .  .  .  .  .  .  .  .  .  `  .  .  .  *  W  .  .  .  .  i  .  .  .  .  .  .  .  .  .  `  .  8  .  .  J  J  .  .  .  .  *  W  `     >  @     X  G     .  E  .  .  W  .  .  .  .  W     J  R  .  .  .  T     .  A  .  .  .  U     `  R  .  .  .  .  W     `  R  .  .  .  .  W     `  R  .  .  .  .  W     `  R  .  .  .  .  W     `  R  .  .  .  .  W     `  R  .  .  .  .  W     `  R  .  .  .  .  W     `  R  .  .     .  R  .  .  .  .  @     .  .  .  .  .  .  .  .  .  .  .  W  .  .  W  .  .  .  T     `  R  .  .  W  .  .  W     .  P  .  .     U  P     .  M     `  R  .  .  W  .  .  W     .  P  .  .     U  P  .  .  )  .     .  M     `  R  .  .  W  .  .  W  .  .     U  P     .  M     .  M     .  M     `  R  .  .  W  .  .  W  .  .     U  P  .  .  )  .     `  R  .  .  W  .  .  W     .  P  .  .     U  P     `  R  .  .  W  .  .  W     .  P  .  .     U  P     `  R  .  .     .  R  L  .  A  L  .  A  `     J  R  .  .  .  .  .  .  [  .  .  .  .  .  .  [  .  .  .  .  .  .  .  .  [  .  .  .  W  .  .  .  .  .  .  [  .  .  .  W  .  .  .  .  .  .  .  .  .  .  .  [  .  .  .  .  .  .  .  .  [  .     .  .  B  .  .  \  .  .  A  .  .  A  .  .  \  .  .  A  .  .  A  .  .  .  .  A  .  .  A  .  .  .  .  .  .  .  B  .  .  .  .  .  .  B  .  .  .  .  B  .  .  \  .  .  B  .  .  \  .
AppleWin ->  FujiNet c0 8c 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 8c 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 8d 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 8d 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 8e 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 8e 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 8f 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 8f 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 90 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 90 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 91 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 91 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 92 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 92 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 93 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 93 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 94 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 94 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 95 01 01 00 02 30 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  0  .  .  .
 FujiNet -> AppleWin c0 95 00 8d 08 42 ea ea ea ea ea ea 8e 07 5c 8c 08 5c 8d 06 5c a2 00 ad 08 5c aa a9 00 20 60 52 a2 00 ad 07 5c 20 ce 51 8d f6 5b 8e f7 5b a2 00 ad 06 5c 8d f9 5b a2 00 ad 06 5c 10 01 ca 4c 3e 42 20 3d 50 60 20 4a 52 a2 00 a9 00 8d f9 5b a2 00 a9 03 8d fa 5b a0 01 a2 00 b1 80 8d fb 5b a9 f6 a2 57 a2 00 a2 00 8d fc 5b a9 f6 a2 57 8a a2 00 a2 00 a2 00 a2 00 8d fd 5b a0 00 a2 00 b1 80 8d fe 5b a9 20 8d bf 42 ad 09 5c 8d a2 42 8d a9 42 ad 0a 5c 8d a3 42 8d aa 42 a9 bd 8d a1 42 8d a8 42 a2 00 ea ea ea 8d db dc 42 e8 ea ea ea 8d c1 42 a9 04 8d c2 42 ad 04 5c 8d c3 42 ad 05 5c 8d c4 42 ea ea ea ea ea ea 8d 06 5c a2 00 ad 06 5c 8d f9 5b a2 00 ad 06 5c 10 01 ca 4c db dd 42 20 3d 50 60 20 4a 52 a2 00 a9 00 8d f9 5b a2 00 a9 01 8d fa 5b a0 00 a2 00 b1 80 8d fb 5b a9 20 8d 38 43 ad 09 5c 8d 1b 43 8d 22 43 ad 0a 5c 8d 1c 43 8d 23 43 a9 bd 8d 1a 43 8d 21 43 a2 00 ea ea ea 8d 39 43 e8 ea ea ea 8d 3a 43 a9 06 8d 3b 43 ad 04 5c 8d 3c 43 ad 05 5c 8d 3d 43 ea ea ea ea ea ea 8d 06 5c a2 00 ad 06 5c 8d f9 5b a2 00 ad 06 5c 10 01 ca 4c 54 43 20 2e 50 60 20 4a 52 a2 00 a9 00 8d f9 5b a2 00 a9 01 8d fa 5b a0 00 a2 00 b1 80 8d fb 5b a9 fa a2 5b a2 00 a2 00 8d 04 5c a9 fa a2 5b 8a a2 00 a2 00 a2 00 a2 00 8d 05 5c a9 20 8d cc 43 ad 09 5c 8d af 43 8d b6 43 ad 0a 5c 8d b0 43 8d b7 43 a9 bd 8d ae 43 8d b5 43 a2 00 ea ea ea 8d cd 43 e8 ea ea ea 8d ce 43 a9 07 8d cf 43 ad 04 5c 8d d0 43 ad 05 5c 8d d1 43 ea ea ea ea ea ea 8d 06 5c a2 00 ad 06 5c 8d f9 5b a2 00 ad 06 5c 10 01 ca 4c e8 43 20 2e 50 60 20 60 52 a2 00 a9 00 8d f9 5b a2 00 a9 04 8d fa 5b a0 02 a2 c0
 FujiNet -> AppleWin  .  .  .  .  .  B  .  .  .  .  .  .  .  .  \  .  .  \  .  .  \  .  .  .  .  \  .  .  .     `  R  .  .  .  .  \     .  Q  .  .  [  .  .  [  .  .  .  .  \  .  .  [  .  .  .  .  \  .  .  .  L  >  B     =  P  `     J  R  .  .  .  .  .  .  [  .  .  .  .  .  .  [  .  .  .  .  .  .  .  .  [  .  .  .  W  .  .  .  .  .  .  [  .  .  .  W  .  .  .  .  .  .  .  .  .  .  .  [  .  .  .  .  .  .  .  .  [  .     .  .  B  .  .  \  .  .  B  .  .  B  .  .  \  .  .  B  .  .  B  .  .  .  .  B  .  .  B  .  .  .  .  .  .  .  .  B  .  .  .  .  .  .  B  .  .  .  .  B  .  .  \  .  .  B  .  .  \  .  .  B  .  .  .  .  .  .  .  .  \  .  .  .  .  \  .  .  [  .  .  .  .  \  .  .  .  L  .  .  B     =  P  `     J  R  .  .  .  .  .  .  [  .  .  .  .  .  .  [  .  .  .  .  .  .  .  .  [  .     .  8  C  .  .  \  .  .  C  .  "  C  .  .  \  .  .  C  .  #  C  .  .  .  .  C  .  !  C  .  .  .  .  .  .  9  C  .  .  .  .  .  :  C  .  .  .  ;  C  .  .  \  .  <  C  .  .  \  .  =  C  .  .  .  .  .  .  .  .  \  .  .  .  .  \  .  .  [  .  .  .  .  \  .  .  .  L  T  C     .  P  `     J  R  .  .  .  .  .  .  [  .  .  .  .  .  .  [  .  .  .  .  .  .  .  .  [  .  .  .  [  .  .  .  .  .  .  \  .  .  .  [  .  .  .  .  .  .  .  .  .  .  .  \  .     .  .  C  .  .  \  .  .  C  .  .  C  .  .  \  .  .  C  .  .  C  .  .  .  .  C  .  .  C  .  .  .  .  .  .  .  C  .  .  .  .  .  .  C  .  .  .  .  C  .  .  \  .  .  C  .  .  \  .  .  C  .  .  .  .  .  .  .  .  \  .  .  .  .  \  .  .  [  .  .  .  .  \  .  .  .  L  .  C     .  P  `     `  R  .  .  .  .  .  .  [  .  .  .  .  .  .  [  .  .  .  .
AppleWin ->  FujiNet c0 96 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 96 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 97 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 97 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 98 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 98 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 99 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 99 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 9a 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 9a 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 9b 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 9b 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 9c 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 9c 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 9d 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 9d 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 9e 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 9e 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 9f 01 01 00 02 31 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  1  .  .  .
 FujiNet -> AppleWin c0 9f 00 00 b1 80 8d fb 5b a9 f6 a2 57 a2 00 a2 00 8d fc 5b a9 f6 a2 57 8a a2 00 a2 00 a2 00 a2 00 8d fd 5b a0 01 20 60 50 a2 00 a2 00 8d fe 5b a0 01 a2 00 b1 80 a2 00 a2 00 8d ff 5b a9 20 8d 79 44 ad 09 5c 8d 5c 44 8d 63 44 ad 0a 5c 8d 5d 44 8d 64 44 a9 bd 8d 5b 44 8d 62 44 a2 00 ea ea ea 8d 7a 44 e8 ea ea ea 8d 7b 44 a9 08 8d 7c 44 ad 04 5c 8d 7d 44 ad 05 5c 8d 7e 44 ea ea ea ea ea ea 8d 06 5c a2 00 ad 06 5c 8d f9 5b a2 00 ad 06 5c 10 01 ca 4c 95 44 20 4b 50 60 20 60 52 a2 00 a9 00 8d f9 5b a2 00 a9 04 8d fa 5b a0 02 a2 00 b1 80 8d fb 5b a9 f6 a2 57 a2 00 a2 00 8d fc 5b a9 f6 a2 57 8a a2 00 a2 00 a2 00 a2 00 8d fd 5b a0 01 20 60 50 a2 00 a2 00 8d fe 5b a0 01 a2 00 b1 80 a2 00 a2 00 8d ff 5b a2 00 a9 00 8d 00 5c a2 00 a9 00 8d 01 5c a2 00 a9 00 8d 02 5c a9 20 8d 3b 45 ad 09 5c 8d 1e 45 8d 25 45 ad 0a 5c 8d 1f 45 8d 26 45 a9 bd 8d 1d 45 8d 24 45 a2 00 ea ea ea 8d 3c 45 e8 ea ea ea 8d 3d 45 a9 09 8d 3e 45 ad 04 5c 8d 3f 45 ad 05 5c 8d 40 45 ea ea ea ea ea ea 8d 06 5c a2 00 ad 06 5c 8d f9 5b a2 00 ad 06 5c 10 01 ca 4c 57 45 20 4b 50 60 a0 0e b9 18 56 99 0b 5c 88 10 f7 a9 0b a2 5c 20 60 52 a9 0f 20 d4 48 8d 1a 5c ad 1a 5c d0 0f a9 86 a2 55 20 60 52 a0 02 20 0e 52 20 28 4e a2 00 ad 1a 5c 10 01 ca 60 a0 07 b9 27 56 99 1b 5c 88 10 f7 a9 1b a2 5c 20 60 52 a9 08 20 d4 48 8d 23 5c ad 23 5c d0 0f a9 c4 a2 55 20 60 52 a0 02 20 0e 52 20 28 4e a2 00 ad 23 5c 10 01 ca 60 a0 08 b9 2f 56 99 24 5c 88 10 f7 a9 24 a2 5c 20 60 52 a9 09 20 d4 48 8d 2d 5c ad 2d 5c d0 0f a9 f7 a2 55 20 60 52 a0 02 20 0e 52 20 28 4e a2 00 ad 2d 5c 10 01 ca 60 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  [  .  .  .  W  .  .  .  .  .  .  [  .  .  .  W  .  .  .  .  .  .  .  .  .  .  .  [  .  .     `  P  .  .  .  .  .  .  [  .  .  .  .  .  .  .  .  .  .  .  .  [  .     .  y  D  .  .  \  .  \  D  .  c  D  .  .  \  .  ]  D  .  d  D  .  .  .  [  D  .  b  D  .  .  .  .  .  .  z  D  .  .  .  .  .  .  D  .  .  .  .  D  .  .  \  .  .  D  .  .  \  .  .  D  .  .  .  .  .  .  .  .  \  .  .  .  .  \  .  .  [  .  .  .  .  \  .  .  .  L  .  D     K  P  `     `  R  .  .  .  .  .  .  [  .  .  .  .  .  .  [  .  .  .  .  .  .  .  .  [  .  .  .  W  .  .  .  .  .  .  [  .  .  .  W  .  .  .  .  .  .  .  .  .  .  .  [  .  .     `  P  .  .  .  .  .  .  [  .  .  .  .  .  .  .  .  .  .  .  .  [  .  .  .  .  .  .  \  .  .  .  .  .  .  \  .  .  .  .  .  .  \  .     .  ;  E  .  .  \  .  .  E  .  %  E  .  .  \  .  .  E  .  &  E  .  .  .  .  E  .  $  E  .  .  .  .  .  .  <  E  .  .  .  .  .  =  E  .  .  .  >  E  .  .  \  .  ?  E  .  .  \  .  @  E  .  .  .  .  .  .  .  .  \  .  .  .  .  \  .  .  [  .  .  .  .  \  .  .  .  L  W  E     K  P  `  .  .  .  .  V  .  .  \  .  .  .  .  .  .  \     `  R  .  .     .  H  .  .  \  .  .  \  .  .  .  .  .  U     `  R  .  .     .  R     (  N  .  .  .  .  \  .  .  .  `  .  .  .  '  V  .  .  \  .  .  .  .  .  .  \     `  R  .  .     .  H  .  #  \  .  #  \  .  .  .  .  .  U     `  R  .  .     .  R     (  N  .  .  .  #  \  .  .  .  `  .  .  .  /  V  .  $  \  .  .  .  .  $  .  \     `  R  .  .     .  H  .  -  \  .  -  \  .  .  .  .  .  U     `  R  .  .     .  R     (  N  .  .  .  -  \  .  .  .  `  .
AppleWin ->  FujiNet c0 a0 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a0 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 a1 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a1 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 a2 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a2 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 a3 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a3 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 a4 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a4 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 a5 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a5 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 a6 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a6 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 a7 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a7 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 a8 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 a8 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 a9 01 01 00 02 32 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  2  .  .  .
 FujiNet -> AppleWin c0 a9 00 a0 05 b9 38 56 99 2e 5c 88 10 f7 a9 2e a2 5c 20 60 52 a9 06 20 d4 48 8d 34 5c ad 34 5c d0 0f a9 e7 a2 55 20 60 52 a0 02 20 0e 52 20 28 4e a2 00 ad 34 5c 10 01 ca 60 a0 03 b9 3e 56 99 35 5c 88 10 f7 a9 35 a2 5c 20 60 52 a9 04 20 d4 48 8d 39 5c ad 39 5c d0 0f a9 07 a2 56 20 60 52 a0 02 20 0e 52 20 28 4e a2 00 ad 39 5c 10 01 ca 60 a0 07 b9 42 56 99 3a 5c 88 10 f7 a9 3a a2 5c 20 60 52 a9 08 20 d4 48 8d 42 5c ad 42 5c d0 0f a9 b2 a2 55 20 60 52 a0 02 20 0e 52 20 28 4e a2 00 ad 42 5c 10 01 ca 60 a9 00 8d 43 5c a9 07 8d 43 5c a2 00 ad 43 5c f0 6a 8a 18 48 a9 db dc 6d 43 5c aa 68 8d 44 5c 8e 45 5c 20 06 50 85 88 86 89 a2 00 a1 88 c9 20 d0 45 ad 44 5c ae 45 5c 20 14 50 85 88 86 89 a2 00 a1 88 d0 32 ad 44 5c ae 45 5c 20 19 50 85 88 86 89 a2 00 a1 88 c9 03 d0 1d ad 44 5c ae 45 5c 20 1e 50 85 88 86 89 a0 00 b1 88 f0 05 a2 00 4c 1a 47 aa ad 43 5c 60 ce 43 5c 4c b1 46 60 20 4a 52 a9 00 18 48 a9 db dc a0 00 71 80 aa 68 8d 46 5c 8e 47 5c 88 20 25 50 85 88 86 89 a0 00 b1 88 8d 48 5c ad 46 5c ae 47 5c 18 6d 48 5c 90 01 e8 20 14 50 4c 2e 50 20 a5 46 8d 49 5c ad 49 5c f0 0c 20 21 47 8d 32 57 8e 33 57 4c 7b 47 a9 69 a2 55 20 60 52 a0 02 20 5c 4e a9 fa 8d 04 5c a2 5b 8e 05 5c a9 32 8d 09 5c a2 57 8e 0a 5c 20 5b 45 8d 4a 5c a2 00 ad 4a 5c d0 10 a9 9f a2 55 20 60 52 a0 02 20 5c 4e a2 00 8a 60 a9 01 60 a9 00 20 4a 52 20 86 41 8d 4b 5c ad f6 57 8d 4c 5c ee 4c 5c a9 01 8d 4d 5c a2 00 ad 4d 5c 10 01 ca 20 60 52 a2 00 ad 4c 5c 10 01 ca 20 da 4f 10 6b a9 d6 a2 55 20 60 52 a2 00 ad 4d 5c 10 01 ca 20 60 52 a0 04 20 5c 4e ad 4d 5c 20 4a 52 a9 03 20 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  8  V  .  .  \  .  .  .  .  .  .  \     `  R  .  .     .  H  .  4  \  .  4  \  .  .  .  .  .  U     `  R  .  .     .  R     (  N  .  .  .  4  \  .  .  .  `  .  .  .  >  V  .  5  \  .  .  .  .  5  .  \     `  R  .  .     .  H  .  9  \  .  9  \  .  .  .  .  .  V     `  R  .  .     .  R     (  N  .  .  .  9  \  .  .  .  `  .  .  .  B  V  .  :  \  .  .  .  .  :  .  \     `  R  .  .     .  H  .  B  \  .  B  \  .  .  .  .  .  U     `  R  .  .     .  R     (  N  .  .  .  B  \  .  .  .  `  .  .  .  C  \  .  .  .  C  \  .  .  .  C  \  .  j  .  .  H  .  .  .  m  C  \  .  h  .  D  \  .  E  \     .  P  .  .  .  .  .  .  .  .  .     .  E  .  D  \  .  E  \     .  P  .  .  .  .  .  .  .  .  .  2  .  D  \  .  E  \     .  P  .  .  .  .  .  .  .  .  .  .  .  .  .  D  \  .  E  \     .  P  .  .  .  .  .  .  .  .  .  .  .  .  L  .  G  .  .  C  \  `  .  C  \  L  .  F  `     J  R  .  .  .  H  .  .  .  .  .  q  .  .  h  .  F  \  .  G  \  .     %  P  .  .  .  .  .  .  .  .  .  H  \  .  F  \  .  G  \  .  m  H  \  .  .  .     .  P  L  .  P     .  F  .  I  \  .  I  \  .  .     !  G  .  2  W  .  3  W  L  .  G  .  i  .  U     `  R  .  .     \  N  .  .  .  .  \  .  [  .  .  \  .  2  .  .  \  .  W  .  .  \     [  E  .  J  \  .  .  .  J  \  .  .  .  .  .  U     `  R  .  .     \  N  .  .  .  `  .  .  `  .  .     J  R     .  A  .  K  \  .  .  W  .  L  \  .  L  \  .  .  .  M  \  .  .  .  M  \  .  .  .     `  R  .  .  .  L  \  .  .  .     .  O  .  k  .  .  .  U     `  R  .  .  .  M  \  .  .  .     `  R  .  .     \  N  .  M  \     J  R  .  .     .
AppleWin ->  FujiNet c0 aa 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 aa 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 ab 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ab 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 ac 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ac 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 ad 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ad 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 ae 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ae 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 af 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 af 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 b0 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b0 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 b1 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b1 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 b2 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b2 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 b3 01 01 00 02 33 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  3  .  .  .
 FujiNet -> AppleWin c0 b3 00 86 41 8d 4b 5c a9 00 8d 4e 5c a2 00 ad 4e 5c 10 01 ca cd fa 57 8a e9 00 50 02 49 80 10 20 a2 00 ad 4e 5c 10 01 ca 20 19 50 85 88 8a 18 69 57 85 89 a0 f6 b1 88 20 8b 4e ee 4e 5c 4c 0a 48 a9 15 a2 56 20 d3 4e ee 4d 5c 4c c8 47 60 20 4a 52 a0 00 b1 80 20 4a 52 a9 53 20 86 41 8d 51 5c ad 51 5c f0 0e a2 00 ad 51 5c 10 01 ca 20 be 51 4c 2e 50 8d 50 5c ad f6 57 8d 4f 5c ae f7 57 ad f6 57 8d 4f 5c 8e 50 5c 4c 2e 50 20 4a 52 a0 00 b1 80 20 4a 52 a9 53 20 86 41 8d 52 5c ad 52 5c f0 11 a2 00 ad 52 5c 20 be 51 a2 00 c9 80 90 0a 4c b7 48 aa ad f8 57 10 01 ca 4c 2e 50 20 4a 52 a9 00 8d f6 57 8d f7 57 a8 b1 80 20 4a 52 a9 41 20 42 42 4c 2e 50 20 4a 52 a9 00 8d 57 5c a8 b1 80 38 e9 01 91 80 98 20 4a 52 20 86 41 8d 53 5c ad 53 5c f0 17 a2 00 ad 53 5c 10 01 ca 20 be 51 a2 00 c9 80 b0 03 4c df 49 4c de 49 ad f6 57 8d 54 5c ee 54 5c a9 01 8d 55 5c a2 00 ad 55 5c 10 01 ca 20 60 52 a2 00 ad 54 5c 10 01 ca 20 da 4f 30 03 4c ce 49 ad 55 5c 20 4a 52 a9 03 20 86 41 8d 53 5c ad 53 5c f0 03 4c c8 49 ad fa 57 20 5e 52 a0 02 b1 80 10 02 a2 ff 20 da 4f d0 6c a9 01 8d 57 5c a9 00 8d 56 5c a2 00 ad 56 5c 10 01 ca 20 60 52 a0 02 a2 00 b1 80 10 01 ca 20 da 4f 10 44 a2 00 ad 56 5c 10 01 ca 18 a0 01 71 80 85 88 8a c8 71 80 85 89 a0 00 b1 88 85 82 a2 00 ad 56 5c 10 01 ca 20 19 50 85 88 8a 18 69 57 85 89 a0 f6 b1 88 c5 82 f0 08 a9 00 8d 57 5c 4c c3 49 ee 56 5c 4c 66 49 ad 57 5c d0 06 ee 55 5c 4c 18 49 ad 57 5c d0 04 aa 4c 4b 50 a2 00 ad 55 5c 10 01 ca 4c 4b 50 20 a0 4d 8d 59 5c a9 ff aa 60 8d 59 5c aa f0 09 20 de 51 20 a0 4d a9 ff aa 60 a0 00 b1 96 c0
 FujiNet -> AppleWin  .  .  .  .  A  .  K  \  .  .  .  N  \  .  .  .  N  \  .  .  .  .  .  W  .  .  .  P  .  I  .  .     .  .  .  N  \  .  .  .     .  P  .  .  .  .  i  W  .  .  .  .  .  .     .  N  .  N  \  L  .  H  .  .  .  V     .  N  .  M  \  L  .  G  `     J  R  .  .  .  .     J  R  .  S     .  A  .  Q  \  .  Q  \  .  .  .  .  .  Q  \  .  .  .     .  Q  L  .  P  .  P  \  .  .  W  .  O  \  .  .  W  .  .  W  .  O  \  .  P  \  L  .  P     J  R  .  .  .  .     J  R  .  S     .  A  .  R  \  .  R  \  .  .  .  .  .  R  \     .  Q  .  .  .  .  .  .  L  .  H  .  .  .  W  .  .  .  L  .  P     J  R  .  .  .  .  W  .  .  W  .  .  .     J  R  .  A     B  B  L  .  P     J  R  .  .  .  W  \  .  .  .  8  .  .  .  .  .     J  R     .  A  .  S  \  .  S  \  .  .  .  .  .  S  \  .  .  .     .  Q  .  .  .  .  .  .  L  .  I  L  .  I  .  .  W  .  T  \  .  T  \  .  .  .  U  \  .  .  .  U  \  .  .  .     `  R  .  .  .  T  \  .  .  .     .  O  0  .  L  .  I  .  U  \     J  R  .  .     .  A  .  S  \  .  S  \  .  .  L  .  I  .  .  W     ^  R  .  .  .  .  .  .  .  .     .  O  .  l  .  .  .  W  \  .  .  .  V  \  .  .  .  V  \  .  .  .     `  R  .  .  .  .  .  .  .  .  .     .  O  .  D  .  .  .  V  \  .  .  .  .  .  .  q  .  .  .  .  .  q  .  .  .  .  .  .  .  .  .  .  .  .  V  \  .  .  .     .  P  .  .  .  .  i  W  .  .  .  .  .  .  .  .  .  .  .  .  .  W  \  L  .  I  .  V  \  L  f  I  .  W  \  .  .  .  U  \  L  .  I  .  W  \  .  .  .  L  K  P  .  .  .  U  \  .  .  .  L  K  P     .  M  .  Y  \  .  .  .  `  .  Y  \  .  .  .     .  Q     .  M  .  .  .  `  .  .  .  .  .
AppleWin ->  FujiNet c0 b4 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b4 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 b5 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b5 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 b6 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b6 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 b7 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b7 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 b8 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b8 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 b9 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 b9 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 ba 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ba 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 bb 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 bb 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 bc 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 bc 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 bd 01 01 00 02 34 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  4  .  .  .
 FujiNet -> AppleWin c0 bd 00 e6 96 d0 02 e6 97 60 ad 65 5c 8d 60 5c 20 a8 4a a9 60 a2 5c 20 60 52 20 41 52 4c 52 57 a5 94 38 e9 02 85 94 b0 02 c6 95 60 ad 6a 5c d0 11 20 46 4a 4c 0a 4e ad 6a 5c d0 06 20 46 4a 4c 04 4e 20 46 4a 85 82 86 83 20 1d 4a a0 01 b1 94 aa 88 b1 94 60 a0 00 84 88 84 89 b1 96 38 e9 30 90 2c c9 0a b0 28 20 00 4a 48 a5 88 a6 89 06 88 26 89 06 88 26 89 65 88 85 88 8a 65 89 85 89 06 88 26 89 68 65 88 85 88 90 d1 e6 89 b0 cd a5 88 a6 89 60 ac 6c 5c ee 6c 5c 99 6d 5c 60 a9 6d a2 5c 18 6d 6c 5c 90 01 e8 4c 60 52 a5 98 a6 99 4c 60 52 20 07 4a ee 66 5c d0 f8 ee 67 5c d0 f3 60 20 a8 4a ad 81 5c ae 82 5c 20 60 52 ad 83 5c ae 84 5c 20 60 52 4c 52 57 84 88 20 8e 50 20 9a 4a a5 88 4c be 50 84 88 20 8e 50 20 9a 4a a5 88 4c ff 50 48 a0 05 b9 94 00 99 5a 5c 88 10 f7 68 85 94 86 95 20 35 50 85 96 86 97 20 35 50 85 98 86 99 a9 00 a8 91 98 c8 91 98 c8 b1 98 8d 53 57 c8 b1 98 8d 54 57 a5 96 85 88 a5 97 85 89 a0 00 b1 96 f0 0b c9 25 f0 07 c8 d0 f5 e6 97 d0 f1 98 18 65 96 85 96 90 02 e6 97 38 e5 88 85 8a a5 97 e5 89 85 8b 05 8a f0 25 20 29 4f a0 05 a5 99 91 80 88 a5 98 91 80 88 a5 89 91 80 88 a5 88 91 80 88 a5 8b 91 80 88 a5 8a 91 80 20 52 57 20 fc 49 aa d0 0b a2 05 bd 5a 5c 95 94 ca 10 f8 60 c9 25 d0 09 b1 96 c9 25 d0 09 20 00 4a 20 0a 4a 4c 22 4b a9 00 a2 0b 9d 61 5c ca 10 fa b1 96 c9 2d d0 05 8e 61 5c f0 19 c9 2b d0 05 8e 62 5c f0 10 c9 20 d0 05 8e 63 5c f0 07 c9 23 d0 09 8e 64 5c 20 00 4a 4c a7 4b a2 20 c9 30 d0 06 aa 20 00 4a b1 96 8e 65 5c c9 2a d0 09 20 00 4a 20 46 4a 4c f0 4b 20 52 4a 8d 66 5c 8e 67 5c 8c 68 5c 8c 69 5c b1 96 c9 2e c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  .  `  .  e  \  .  `  \     .  J  .  `  .  \     `  R     A  R  L  R  W  .  .  8  .  .  .  .  .  .  .  .  `  .  j  \  .  .     F  J  L  .  N  .  j  \  .  .     F  J  L  .  N     F  J  .  .  .  .     .  J  .  .  .  .  .  .  .  .  `  .  .  .  .  .  .  .  .  8  .  0  .  ,  .  .  .  (     .  J  H  .  .  .  .  .  .  &  .  .  .  &  .  e  .  .  .  .  e  .  .  .  .  .  &  .  h  e  .  .  .  .  .  .  .  .  .  .  .  .  .  `  .  l  \  .  l  \  .  m  \  `  .  m  .  \  .  m  l  \  .  .  .  L  `  R  .  .  .  .  L  `  R     .  J  .  f  \  .  .  .  g  \  .  .  `     .  J  .  .  \  .  .  \     `  R  .  .  \  .  .  \     `  R  L  R  W  .  .     .  P     .  J  .  .  L  .  P  .  .     .  P     .  J  .  .  L  .  P  H  .  .  .  .  .  .  Z  \  .  .  .  h  .  .  .  .     5  P  .  .  .  .     5  P  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  S  W  .  .  .  .  T  W  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  %  .  .  .  .  .  .  .  .  .  .  .  e  .  .  .  .  .  .  .  8  .  .  .  .  .  .  .  .  .  .  .  .  .  %     )  O  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .     R  W     .  I  .  .  .  .  .  .  Z  \  .  .  .  .  .  `  .  %  .  .  .  .  .  %  .  .     .  J     .  J  L  "  K  .  .  .  .  .  a  \  .  .  .  .  .  .  -  .  .  .  a  \  .  .  .  +  .  .  .  b  \  .  .  .     .  .  .  c  \  .  .  .  #  .  .  .  d  \     .  J  L  .  K  .     .  0  .  .  .     .  J  .  .  .  e  \  .  *  .  .     .  J     F  J  L  .  K     R  J  .  f  \  .  g  \  .  h  \  .  i  \  .  .  .  .  .
AppleWin ->  FujiNet c0 be 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 be 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 bf 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 bf 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 db dc 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .
 FujiNet -> AppleWin c0 db dc 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 c1 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c1 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 c2 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c2 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 c3 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c3 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 c4 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c4 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 c5 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c5 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 c6 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c6 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 c7 01 01 00 02 35 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  5  .  .  .
 FujiNet -> AppleWin c0 c7 00 d0 1b 20 00 4a b1 96 c9 2a d0 09 20 00 4a 20 46 4a 4c 17 4c 20 52 4a 8d 68 5c 8e 69 5c b1 96 c9 7a f0 19 c9 68 f0 15 c9 74 f0 11 c9 6a f0 08 c9 4c f0 04 c9 6c d0 0b a9 ff 8d 6a 5c 20 00 4a 4c 1d 4c 8c 6c 5c a2 6d 8e 81 5c a2 5c 8e 82 5c 20 00 4a c9 63 d0 0d 20 46 4a 8d 6d 5c a2 00 a9 01 4c 49 4d c9 64 f0 04 c9 69 d0 2d a2 00 ad 63 5c f0 02 a2 20 ad 62 5c f0 02 a2 2b 8e 6b 5c 20 34 4a a4 83 30 0b ac 6b 5c f0 06 8c 6d 5c ee 6c 5c a0 0a 20 d5 4a 4c 40 4d c9 6e d0 15 20 46 4a 85 88 86 89 a0 00 b1 98 91 88 c8 b1 98 91 88 4c 22 4b c9 6f d0 27 20 34 4a ac 64 5c f0 17 48 86 90 05 90 05 82 05 83 0d 68 5c 0d 69 5c f0 06 a9 30 20 90 4a 68 a0 08 20 d5 4a 4c 40 4d c9 70 d0 0d a2 00 8e 6a 5c e8 8e 64 5c a9 78 d0 27 c9 73 d0 0c 20 46 4a 8d 81 5c 8e 82 5c 4c 40 4d c9 75 d0 0b 20 29 4a a0 0a 20 e2 4a 4c 40 4d c9 78 f0 04 c9 58 d0 29 48 ad 64 5c f0 0a a9 30 20 90 4a a9 58 20 90 4a 20 29 4a a0 10 20 e2 4a 68 c9 78 d0 09 ad 81 5c ae 82 5c 20 e5 52 4c 40 4d 4c 22 4b ad 81 5c ae 82 5c 20 cf 52 8d 83 5c 8e 84 5c ad 68 5c 0d 69 5c f0 15 ae 68 5c ec 83 5c ad 69 5c a8 ed 84 5c b0 06 8e 83 5c 8c 84 5c 38 ad 66 5c ed 83 5c aa ad 67 5c ed 84 5c b0 03 a9 00 aa 49 ff 8d 67 5c 8a 49 ff 8d 66 5c ad 61 5c d0 03 20 b2 4a 20 bd 4a ad 61 5c f0 03 20 b2 4a 4c 22 4b 8d 86 5c a9 00 8d 87 5c 60 a2 00 18 a0 00 71 80 c8 85 90 8a 71 80 aa 18 a5 80 69 02 85 80 90 02 e6 81 a5 90 60 c8 48 18 98 65 80 85 80 90 02 e6 81 68 60 86 90 0a 26 90 0a 26 90 0a 26 90 a6 90 60 86 90 e0 80 66 90 6a a6 90 60 86 90 e0 80 66 90 6a e0 80 66 90 6a e0 80 66 90 6a e0 80 66 90 c0
 FujiNet -> AppleWin  .  .  .  .  .     .  J  .  .  .  *  .  .     .  J     F  J  L  .  L     R  J  .  h  \  .  i  \  .  .  .  z  .  .  .  h  .  .  .  t  .  .  .  j  .  .  .  L  .  .  .  l  .  .  .  .  .  j  \     .  J  L  .  L  .  l  \  .  m  .  .  \  .  \  .  .  \     .  J  .  c  .  .     F  J  .  m  \  .  .  .  .  L  I  M  .  d  .  .  .  i  .  -  .  .  .  c  \  .  .  .     .  b  \  .  .  .  +  .  k  \     4  J  .  .  0  .  .  k  \  .  .  .  m  \  .  l  \  .  .     .  J  L  @  M  .  n  .  .     F  J  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  L  "  K  .  o  .  '     4  J  .  d  \  .  .  H  .  .  .  .  .  .  .  .  .  h  \  .  i  \  .  .  .  0     .  J  h  .  .     .  J  L  @  M  .  p  .  .  .  .  .  j  \  .  .  d  \  .  x  .  '  .  s  .  .     F  J  .  .  \  .  .  \  L  @  M  .  u  .  .     )  J  .  .     .  J  L  @  M  .  x  .  .  .  X  .  )  H  .  d  \  .  .  .  0     .  J  .  X     .  J     )  J  .  .     .  J  h  .  x  .  .  .  .  \  .  .  \     .  R  L  @  M  L  "  K  .  .  \  .  .  \     .  R  .  .  \  .  .  \  .  h  \  .  i  \  .  .  .  h  \  .  .  \  .  i  \  .  .  .  \  .  .  .  .  \  .  .  \  8  .  f  \  .  .  \  .  .  g  \  .  .  \  .  .  .  .  .  I  .  .  g  \  .  I  .  .  f  \  .  a  \  .  .     .  J     .  J  .  a  \  .  .     .  J  L  "  K  .  .  \  .  .  .  .  \  `  .  .  .  .  .  q  .  .  .  .  .  q  .  .  .  .  .  i  .  .  .  .  .  .  .  .  .  `  .  H  .  .  e  .  .  .  .  .  .  .  h  `  .  .  .  &  .  .  &  .  .  &  .  .  .  `  .  .  .  .  f  .  j  .  .  `  .  .  .  .  f  .  j  .  .  f  .  j  .  .  f  .  j  .  .  f  .  .
AppleWin ->  FujiNet c0 c8 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c8 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 c9 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 c9 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 ca 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ca 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 cb 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 cb 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 cc 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 cc 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 cd 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 cd 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 ce 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ce 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 cf 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 cf 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 d0 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d0 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 d1 01 01 00 02 36 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  6  .  .  .
 FujiNet -> AppleWin c0 d1 00 6a a6 90 60 a0 ff e0 80 b0 02 a0 00 84 82 84 83 60 ad 55 57 ae 56 57 20 60 52 ad 57 57 ae 58 57 20 60 52 a0 04 4c 88 40 ad 58 5c f0 05 a9 60 20 bf 4e e6 4e d0 02 e6 4f ad 00 db dc 10 f5 ac 58 5c f0 06 48 8a 20 bf 4e 68 2c 10 db dc 29 7f a2 00 60 a0 00 f0 07 a9 2a a2 57 4c 59 57 60 8c 85 5c 88 88 98 18 65 80 85 88 a6 81 90 01 e8 86 89 a0 01 b1 88 aa 88 b1 88 20 60 52 a5 88 a6 89 20 a3 53 ac 85 5c 4c c6 4d 48 20 c7 4f 68 c9 0d f0 1a c9 0a f0 1b 49 80 c9 e0 90 02 29 df 20 bd 4e e6 24 a5 24 c5 21 90 07 20 ae 4e a9 00 85 24 60 e6 25 a5 25 c5 23 90 04 a5 22 85 25 4c 48 40 25 32 48 a4 24 b1 28 aa 68 91 28 60 85 88 86 89 20 c7 4f 4c d7 4e 85 88 86 89 a0 00 b1 88 f0 0e c8 84 90 20 8b 4e a4 90 d0 f2 e6 89 d0 ee 60 8e f2 03 8d f3 03 49 a5 8d f4 03 60 20 00 bf 65 66 56 e0 00 d0 15 4a aa bd 78 56 90 05 4a 4a 4a 4a 18 29 0f aa bd 6d 56 a2 00 60 38 a9 00 aa 60 a5 80 38 e9 04 85 80 90 01 60 c6 81 60 a5 80 38 e9 06 85 80 90 01 60 c6 81 60 e0 00 d0 0e c9 08 b0 0a 0a 0a a8 b9 82 57 f0 02 18 60 a9 07 38 60 8d 88 5c 85 88 8e 89 5c 86 89 a0 01 b1 88 29 01 d0 09 a9 10 20 a0 4d aa 4c 50 50 b1 88 29 04 d0 f1 a0 00 b1 88 a2 00 20 60 52 a0 09 20 78 52 a0 07 20 78 52 a0 09 20 60 50 20 3b 51 e0 00 d0 0e c9 00 d0 0a a0 05 20 60 50 a0 0a 4c c6 4d 20 34 54 e0 ff d0 18 c9 ff d0 14 ad 88 5c 85 88 ad 89 5c 85 89 a0 01 b1 88 09 04 91 88 d0 a5 20 60 52 a0 05 20 60 50 20 0e 53 4c 50 50 20 f4 51 18 65 22 85 25 20 48 40 20 f4 51 85 24 60 a2 00 85 82 86 83 a0 00 b1 80 aa e6 80 d0 02 e6 81 b1 80 e6 80 d0 02 e6 81 38 e5 83 d0 09 e4 82 f0 04 69 ff 09 01 60 50 c0
 FujiNet -> AppleWin  .  .  .  j  .  .  `  .  .  .  .  .  .  .  .  .  .  .  .  `  .  U  W  .  V  W     `  R  .  W  W  .  X  W     `  R  .  .  L  .  @  .  X  \  .  .  .  `     .  N  .  N  .  .  .  O  .  .  .  .  .  .  .  X  \  .  .  H  .     .  N  h  ,  .  .  .  )  .  .  .  `  .  .  .  .  .  *  .  W  L  Y  W  `  .  .  \  .  .  .  .  e  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .     `  R  .  .  .  .     .  S  .  .  \  L  .  M  H     .  O  h  .  .  .  .  .  .  .  .  I  .  .  .  .  .  )  .     .  N  .  $  .  $  .  !  .  .     .  N  .  .  .  $  `  .  %  .  %  .  #  .  .  .  "  .  %  L  H  @  %  2  H  .  $  .  (  .  h  .  (  `  .  .  .  .     .  O  L  .  N  .  .  .  .  .  .  .  .  .  .  .  .  .     .  N  .  .  .  .  .  .  .  .  `  .  .  .  .  .  .  I  .  .  .  .  `     .  .  e  f  V  .  .  .  .  J  .  .  x  V  .  .  J  J  J  J  .  )  .  .  .  m  V  .  .  `  8  .  .  .  `  .  .  8  .  .  .  .  .  .  `  .  .  `  .  .  8  .  .  .  .  .  .  `  .  .  `  .  .  .  .  .  .  .  .  .  .  .  .  .  W  .  .  .  `  .  .  8  `  .  .  \  .  .  .  .  \  .  .  .  .  .  .  )  .  .  .  .  .     .  M  .  L  P  P  .  .  )  .  .  .  .  .  .  .  .  .     `  R  .  .     x  R  .  .     x  R  .  .     `  P     ;  Q  .  .  .  .  .  .  .  .  .  .     `  P  .  .  L  .  M     4  T  .  .  .  .  .  .  .  .  .  .  \  .  .  .  .  \  .  .  .  .  .  .  .  .  .  .  .  .     `  R  .  .     `  P     .  S  L  P  P     .  Q  .  e  "  .  %     H  @     .  Q  .  $  `  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  8  .  .  .  .  .  .  .  .  i  .  .  .  `  P  .
AppleWin ->  FujiNet c0 d2 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d2 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 d3 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d3 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 d4 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d4 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 d5 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d5 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 d6 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d6 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 d7 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d7 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 d8 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d8 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 d9 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 d9 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 da 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 da 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 db dd 01 01 00 02 37 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  .  7  .  .  .
 FujiNet -> AppleWin c0 db dd 00 fd 49 ff 09 01 60 18 69 01 90 01 e8 60 18 69 02 90 01 e8 60 a0 03 4c 25 50 a0 05 4c 25 50 a0 07 4c 25 50 a0 04 84 90 18 65 90 90 01 e8 60 e6 80 d0 02 e6 81 60 a0 01 b1 80 aa 88 b1 80 e6 80 f0 05 e6 80 f0 03 60 e6 80 e6 81 60 a0 03 4c c6 4d a0 06 4c c6 4d 85 88 86 89 a2 00 b1 88 60 a0 01 b1 80 aa 88 b1 80 60 18 49 ff 69 01 48 8a 49 ff 69 00 aa a5 82 49 ff 69 00 85 82 a5 83 49 ff 69 00 85 83 68 60 a9 00 aa a0 00 84 82 84 83 48 20 1c 4f a0 03 a5 83 91 80 88 a5 82 91 80 88 8a 91 80 68 88 91 80 60 85 90 20 35 50 85 8a 86 8b 85 8c 86 8d 20 00 52 20 35 50 85 82 86 83 60 20 a6 50 a6 83 a4 90 db dc 0a d0 39 a5 82 05 89 05 88 d0 11 e0 80 d0 0d a0 0b b9 5a 56 91 8a 88 10 f8 4c 36 51 8a 10 1d a9 2d a0 00 91 8a e6 8a d0 02 e6 8b a5 88 a6 89 20 67 50 85 88 86 89 4c 02 51 20 a6 50 a9 00 48 a0 20 a9 00 06 88 26 89 26 82 26 83 2a c5 90 90 04 e5 90 e6 88 88 d0 ec a8 b9 4a 56 48 a5 88 05 89 05 82 05 83 d0 d9 a0 00 68 91 8a f0 03 c8 d0 f8 a5 8c a6 8d 60 85 8e 8a f0 2e 86 8f 20 00 52 98 a4 89 f0 27 85 90 a0 10 46 8f 66 8e 90 0b 18 65 88 aa a5 89 65 90 85 90 8a 66 90 6a 66 8f 66 8e 88 d0 e9 a5 8e a6 8f 60 4c 82 51 86 89 a4 88 a6 8e 86 88 84 8e a0 08 4c 8c 51 85 8e 20 00 52 98 a0 08 a6 89 f0 1d 85 8f 46 8e 90 0b 18 65 88 aa a5 89 65 8f 85 8f 8a 66 8f 6a 66 8e 88 d0 eb aa a5 8e 60 46 8e 90 03 18 65 88 6a 66 8e 88 d0 f5 aa a5 8e 60 e0 00 10 0d 18 49 ff 69 01 48 8a 49 ff 69 00 aa 68 60 a2 00 a0 00 11 80 c8 85 90 8a 11 80 aa a5 90 4c c5 4d a2 32 dd f6 56 f0 09 ca ca d0 f7 a9 12 a2 00 60 bd f7 56 a2 00 60 a0 00 b1 80 e6 80 f0 01 60 e6 81 60 c0
 FujiNet -> AppleWin  .  .  .  .  .  I  .  .  .  `  .  i  .  .  .  .  `  .  i  .  .  .  .  `  .  .  L  %  P  .  .  L  %  P  .  .  L  %  P  .  .  .  .  .  e  .  .  .  .  `  .  .  .  .  .  .  `  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  `  .  .  .  .  `  .  .  L  .  M  .  .  L  .  M  .  .  .  .  .  .  .  .  `  .  .  .  .  .  .  .  .  `  .  I  .  i  .  H  .  I  .  i  .  .  .  .  I  .  i  .  .  .  .  .  I  .  i  .  .  .  h  `  .  .  .  .  .  .  .  .  .  H     .  O  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  h  .  .  .  `  .  .     5  P  .  .  .  .  .  .  .  .     .  R     5  P  .  .  .  .  `     .  P  .  .  .  .  .  .  .  .  9  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  Z  V  .  .  .  .  .  L  6  Q  .  .  .  .  -  .  .  .  .  .  .  .  .  .  .  .  .  .  .     g  P  .  .  .  .  L  .  Q     .  P  .  .  H  .     .  .  .  .  &  .  &  .  &  .  *  .  .  .  .  .  .  .  .  .  .  .  .  .  J  V  H  .  .  .  .  .  .  .  .  .  .  .  .  h  .  .  .  .  .  .  .  .  .  .  .  `  .  .  .  .  .  .  .     .  R  .  .  .  .  '  .  .  .  .  F  .  f  .  .  .  .  e  .  .  .  .  e  .  .  .  .  f  .  j  f  .  f  .  .  .  .  .  .  .  .  `  L  .  Q  .  .  .  .  .  .  .  .  .  .  .  .  L  .  Q  .  .     .  R  .  .  .  .  .  .  .  .  .  F  .  .  .  .  e  .  .  .  .  e  .  .  .  .  f  .  j  f  .  .  .  .  .  .  .  `  F  .  .  .  .  e  .  j  f  .  .  .  .  .  .  .  `  .  .  .  .  .  I  .  i  .  H  .  I  .  i  .  .  h  `  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  L  .  M  .  2  .  .  V  .  .  .  .  .  .  .  .  .  .  `  .  .  V  .  .  `  .  .  .  .  .  .  .  .  `  .  .  `  .
AppleWin ->  FujiNet c0 dc 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 dc 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 dd 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 dd 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 de 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 de 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 df 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 df 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 e0 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e0 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 e1 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e1 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 e2 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e2 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 e3 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e3 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 e4 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e4 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 e5 01 01 00 02 38 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  8  .  .  .
 FujiNet -> AppleWin c0 e5 00 a0 01 b1 80 85 89 88 b1 80 85 88 4c 3d 50 8c 9c 5c ad 4e 57 ae 4f 57 20 60 52 a5 80 a6 81 18 6d 9c 5c 90 01 e8 85 88 86 89 a0 01 b1 88 aa 88 b1 88 20 60 52 a5 88 a6 89 20 0b 54 ac 9c 5c 4c c6 4d a9 01 4c 5e 52 a0 00 b1 80 a4 80 f0 07 c6 80 a0 00 91 80 60 c6 81 c6 80 91 80 60 a9 00 a2 00 48 a5 80 38 e9 02 85 80 b0 02 c6 81 a0 01 8a 91 80 68 88 91 80 60 a0 03 a5 80 38 e9 02 85 80 b0 02 c6 81 b1 80 aa 88 b1 80 a0 00 91 80 c8 8a 91 80 60 85 8a 86 8b 20 00 52 20 35 50 4c 36 4f 8d 8b 5c a5 88 a6 89 8d 8c 5c 8e 8d 5c a5 8a a6 8b 8d 8e 5c 8e 8f 5c 98 a2 04 20 a2 57 90 04 c9 4c d0 0a 8d 59 5c ad 90 5c ae 91 5c 60 4c ec 49 85 8a 86 8b a2 00 a0 00 b1 8a f0 08 c8 d0 f9 e6 8b e8 d0 f4 98 60 85 88 86 89 85 8a 86 8b a0 00 b1 88 f0 14 20 02 4f 29 02 f0 06 b1 88 69 20 91 88 c8 d0 ec e6 89 d0 e8 a5 8a a6 8b 60 a2 00 85 8e 86 8f 20 00 52 20 1d 53 a5 88 a6 89 60 a9 00 85 83 a0 10 a6 8f f0 1f 06 88 26 89 2a 26 83 aa c5 8e a5 83 e5 8f 90 08 85 83 8a e5 8e aa e6 88 8a 88 d0 e4 85 82 60 06 88 26 89 2a b0 04 c5 8e 90 04 e5 8e e6 88 88 d0 ee 85 82 60 20 35 50 85 8a 86 8b e8 8e cd 57 aa e8 8e cc 57 20 00 52 20 35 50 85 8c 86 8d a0 00 84 90 b1 8c 18 65 8a 91 8c c8 b1 8c 65 8b 91 8c ce cc 57 f0 11 a4 90 b1 88 c8 d0 02 e6 89 84 90 20 8b 4e 4c 87 53 ce cd 57 d0 ea 60 85 88 86 89 a9 00 8d c6 57 8d c7 57 a0 01 b1 80 aa 88 b1 80 20 60 52 a0 02 a9 c6 91 80 c8 a9 57 91 80 a5 88 a6 89 20 ef 4a ad c6 57 ae c7 57 60 a0 05 20 78 52 20 41 52 a0 07 20 78 52 ad d2 57 ae d3 57 20 4c 4f 85 88 86 89 05 89 d0 07 a9 ff 8d ce 57 d0 0d a5 88 18 6d ce 57 8d ce c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  .  .  .  .  .  .  L  =  P  .  .  \  .  N  W  .  O  W     `  R  .  .  .  .  .  m  .  \  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .     `  R  .  .  .  .     .  T  .  .  \  L  .  M  .  .  L  ^  R  .  .  .  .  .  .  .  .  .  .  .  .  .  .  `  .  .  .  .  .  .  `  .  .  .  .  H  .  .  8  .  .  .  .  .  .  .  .  .  .  .  .  .  h  .  .  .  `  .  .  .  .  8  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  `  .  .  .  .     .  R     5  P  L  6  O  .  .  \  .  .  .  .  .  .  \  .  .  \  .  .  .  .  .  .  \  .  .  \  .  .  .     .  W  .  .  .  L  .  .  .  Y  \  .  .  \  .  .  \  `  L  .  I  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  `  .  .  .  .  .  .  .  .  .  .  .  .  .  .     .  O  )  .  .  .  .  .  i     .  .  .  .  .  .  .  .  .  .  .  .  .  `  .  .  .  .  .  .     .  R     .  S  .  .  .  .  `  .  .  .  .  .  .  .  .  .  .  .  .  &  .  *  &  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  `  .  .  &  .  *  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  `     5  P  .  .  .  .  .  .  .  W  .  .  .  .  W     .  R     5  P  .  .  .  .  .  .  .  .  .  .  .  e  .  .  .  .  .  .  e  .  .  .  .  .  W  .  .  .  .  .  .  .  .  .  .  .  .  .     .  N  L  .  S  .  .  W  .  .  `  .  .  .  .  .  .  .  .  W  .  .  W  .  .  .  .  .  .  .  .     `  R  .  .  .  .  .  .  .  .  W  .  .  .  .  .  .     .  J  .  .  W  .  .  W  `  .  .     x  R     A  R  .  .     x  R  .  .  W  .  .  W     L  O  .  .  .  .  .  .  .  .  .  .  .  .  W  .  .  .  .  .  m  .  W  .  .  .
AppleWin ->  FujiNet c0 e6 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e6 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 e7 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e7 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 e8 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e8 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 e9 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 e9 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 ea 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ea 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 eb 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 eb 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 ec 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ec 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 ed 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ed 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 ee 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ee 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 ef 01 01 00 02 39 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  9  .  .  .
 FujiNet -> AppleWin c0 ef 00 57 8a 6d cf 57 8d cf 57 4c 50 50 48 a9 00 8d ce 57 8d cf 57 a0 02 b1 80 8d d2 57 a9 ce 91 80 c8 b1 80 8d d3 57 a9 57 91 80 68 20 ef 4a ad ce 57 ae cf 57 60 20 92 52 b0 65 aa b9 83 57 29 02 f0 5b 8a 30 24 b9 83 57 29 40 f0 15 8e 8b 5c a9 d1 a2 02 20 a2 57 b0 4a a9 ce a2 02 20 a2 57 b0 41 b9 82 57 a0 cb 4c 9f 52 a6 8a a5 8b 8e 90 5c 8d 91 5c 05 8a f0 21 a0 00 b1 88 c9 0a d0 02 a9 0d 09 80 c9 e0 90 02 29 df 20 34 40 c8 d0 02 e6 89 ca d0 e5 c6 8b 10 e1 a9 00 4c c2 52 a9 07 4c e2 49 4c ec 49 a9 f3 85 88 a9 57 85 89 a9 00 a8 a2 04 f0 0a 91 88 c8 d0 fb e6 89 ca d0 f6 db dc aa f0 05 91 88 c8 d0 f7 60 0a 0a 55 73 69 6e 67 20 74 68 65 20 50 72 6f 64 6f 73 20 63 61 6c 6c 20 61 6e 64 20 64 72 69 76 65 72 3a 0a 20 20 20 20 44 61 74 65 3a 20 25 30 32 75 2d 25 30 32 75 2d 25 30 32 75 0a 20 20 20 20 54 69 6d 65 3a 20 25 30 32 75 3a 25 30 32 75 0a 00 0a 0a 44 69 72 65 63 74 6c 79 20 66 72 6f 6d 20 46 75 6a 69 6e 65 74 3a 0a 20 20 20 20 44 61 74 65 3a 20 25 30 32 75 25 30 32 75 2d 25 30 32 75 2d 25 30 32 75 0a 20 20 20 20 54 69 6d 65 3a 20 25 30 32 75 3a 25 30 32 75 3a 25 30 32 75 0a 00 4e 6f 20 53 6d 61 72 74 50 6f 72 74 20 46 69 72 6d 77 61 72 65 20 46 6f 75 6e 64 21 00 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 4e 4f 54 20 46 4f 55 4e 44 00 46 75 6a 69 4e 65 74 20 4e 6f 74 20 46 6f 75 6e 64 21 00 50 52 49 4e 54 45 52 20 4e 4f 54 20 46 4f 55 4e 44 00 4e 45 54 57 4f 52 4b 20 4e 4f 54 20 46 4f 55 4e 44 00 55 4e 49 54 20 23 25 32 64 20 4e 41 4d 45 3a 20 00 4d 4f 44 45 4d 20 4e 4f 54 20 46 4f 55 4e 44 00 43 4c 4f 43 4b 20 4e 4f 54 c0
 FujiNet -> AppleWin  .  .  .  W  .  m  .  W  .  .  W  L  P  P  H  .  .  .  .  W  .  .  W  .  .  .  .  .  .  W  .  .  .  .  .  .  .  .  .  W  .  W  .  .  h     .  J  .  .  W  .  .  W  `     .  R  .  e  .  .  .  W  )  .  .  [  .  0  $  .  .  W  )  @  .  .  .  .  \  .  .  .  .     .  W  .  J  .  .  .  .     .  W  .  A  .  .  W  .  .  L  .  R  .  .  .  .  .  .  \  .  .  \  .  .  .  !  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  )  .     4  @  .  .  .  .  .  .  .  .  .  .  .  .  .  .  L  .  R  .  .  L  .  I  L  .  I  .  .  .  .  .  W  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  `  .  .  U  s  i  n  g     t  h  e     P  r  o  d  o  s     c  a  l  l     a  n  d     d  r  i  v  e  r  :  .              D  a  t  e  :     %  0  2  u  -  %  0  2  u  -  %  0  2  u  .              T  i  m  e  :     %  0  2  u  :  %  0  2  u  .  .  .  .  D  i  r  e  c  t  l  y     f  r  o  m     F  u  j  i  n  e  t  :  .              D  a  t  e  :     %  0  2  u  %  0  2  u  -  %  0  2  u  -  %  0  2  u  .              T  i  m  e  :     %  0  2  u  :  %  0  2  u  :  %  0  2  u  .  .  N  o     S  m  a  r  t  P  o  r  t     F  i  r  m  w  a  r  e     F  o  u  n  d  !  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0     N  O  T     F  O  U  N  D  .  F  u  j  i  N  e  t     N  o  t     F  o  u  n  d  !  .  P  R  I  N  T  E  R     N  O  T     F  O  U  N  D  .  N  E  T  W  O  R  K     N  O  T     F  O  U  N  D  .  U  N  I  T     #  %  2  d     N  A  M  E  :     .  M  O  D  E  M     N  O  T     F  O  U  N  D  .  C  L  O  C  K     N  O  T  .
AppleWin ->  FujiNet c0 f0 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f0 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 f1 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f1 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 f2 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f2 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 f3 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f3 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 f4 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f4 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 f5 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f5 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 f6 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f6 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 f7 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f7 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 f8 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 f8 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 f9 01 01 00 02 3a 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  :  .  .  .
 FujiNet -> AppleWin c0 f9 00 20 46 4f 55 4e 44 00 43 50 4d 20 4e 4f 54 20 46 4f 55 4e 44 00 0d 0a 00 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 00 4e 45 54 57 4f 52 4b 00 46 4e 5f 43 4c 4f 43 4b 00 4d 4f 44 45 4d 00 43 50 4d 00 50 52 49 4e 54 45 52 00 30 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46 2d 32 31 34 37 34 38 33 36 34 38 00 04 00 00 00 00 00 00 00 01 02 0c 09 0a 10 40 50 a0 d0 66 66 66 66 a6 88 88 66 66 66 66 66 66 66 66 66 09 00 00 00 00 00 00 00 33 33 33 33 33 00 00 00 50 55 55 25 22 22 22 22 22 22 22 22 22 02 00 00 40 44 44 14 11 11 11 11 11 11 11 11 11 01 00 70 66 66 66 66 a6 88 88 66 66 66 66 66 66 66 66 66 09 00 00 00 00 00 00 00 33 33 33 33 33 00 00 00 50 55 55 25 22 22 22 22 22 22 22 22 22 02 00 00 40 44 44 14 11 11 11 11 11 11 11 11 11 01 00 70 01 0d 04 07 25 02 27 0b 28 04 2b 03 2f 04 40 07 42 05 43 07 44 01 45 01 46 01 47 09 48 08 49 08 4a 11 4b 07 4d 0e 4e 03 50 07 52 04 53 0f 55 05 56 07 00 00 00 00 00 00 00 00 00 00 00 01 00 01 01 00 02 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 34 57 37 57 3a 57 4c 00 00 00 00 00 00 8d 67 57 8e 68 57 8d 6e 57 8e 6f 57 88 b9 ff ff 8d 78 57 88 b9 ff ff 8d 77 57 8c 7a 57 20 ff ff a0 ff d0 e8 60 4c d0 03 00 80 01 00 00 80 02 00 00 80 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 8d b6 57 8e 8a 5c ad 81 57 f0 15 a5 4e 48 a5 4f 48 20 00 bf 00 8a 5c aa 68 85 4f 68 85 4e 8a 60 a9 01 38 60 00 00 5b 53 00 00 00 00 00 00 d3 53 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a9 40 38 e9 08 4a 4a aa a9 ff e0 08 90 c0
 FujiNet -> AppleWin  .  .  .     F  O  U  N  D  .  C  P  M     N  O  T     F  O  U  N  D  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0  .  N  E  T  W  O  R  K  .  F  N  _  C  L  O  C  K  .  M  O  D  E  M  .  C  P  M  .  P  R  I  N  T  E  R  .  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  -  2  1  4  7  4  8  3  6  4  8  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  @  P  .  .  f  f  f  f  .  .  .  f  f  f  f  f  f  f  f  f  .  .  .  .  .  .  .  .  3  3  3  3  3  .  .  .  P  U  U  %  "  "  "  "  "  "  "  "  "  .  .  .  @  D  D  .  .  .  .  .  .  .  .  .  .  .  .  p  f  f  f  f  .  .  .  f  f  f  f  f  f  f  f  f  .  .  .  .  .  .  .  .  3  3  3  3  3  .  .  .  P  U  U  %  "  "  "  "  "  "  "  "  "  .  .  .  @  D  D  .  .  .  .  .  .  .  .  .  .  .  .  p  .  .  .  .  %  .  '  .  (  .  +  .  /  .  @  .  B  .  C  .  D  .  E  .  F  .  G  .  H  .  I  .  J  .  K  .  M  .  N  .  P  .  R  .  S  .  U  .  V  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  4  W  7  W  :  W  L  .  .  .  .  .  .  .  g  W  .  h  W  .  n  W  .  o  W  .  .  .  .  .  x  W  .  .  .  .  .  w  W  .  z  W     .  .  .  .  .  .  `  L  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  W  .  .  \  .  .  W  .  .  .  N  H  .  O  H     .  .  .  .  \  .  h  .  O  h  .  N  .  `  .  .  8  `  .  .  [  S  .  .  .  .  .  .  .  S  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  @  8  .  .  J  J  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 fa 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 fa 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 fb 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 fb 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 fc 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 fc 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 fd 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 fd 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 fe 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 fe 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 ff 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 ff 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 00 00 07 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 00 00 30 00 00 00 07 4e 45 54 57 4f 52 4b 20 20 20 20 20 20 20 20 20 11 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  N  E  T  W  O  R  K                             .  .  .  .  .
AppleWin ->  FujiNet c0 01 00 08 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 01 00 70 00 00 00 07 50 52 49 4e 54 45 52 20 20 20 20 20 20 20 20 20 14 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  p  .  .  .  .  P  R  I  N  T  E  R                             .  .  .  .  .
AppleWin ->  FujiNet c0 02 00 09 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 02 00 30 00 00 00 05 4d 4f 44 45 4d 20 20 20 20 20 20 20 20 20 20 20 15 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  M  O  D  E  M                                   .  .  .  .  .
AppleWin ->  FujiNet c0 03 01 01 00 02 3b 00 00 c0
AppleWin ->  FujiNet  .  .  .  .  .  .  ;  .  .  .
 FujiNet -> AppleWin c0 03 00 01 60 9d 2a 57 e8 d0 f5 a0 04 f0 07 a9 92 a2 58 4c 59 57 60 a2 19 b5 80 9d d6 57 ca 10 f8 a2 02 bd f2 03 9d f0 57 ca 10 f7 ac 00 bf db dc 4c d0 17 ad 6f bf c9 01 d0 10 a9 f8 a2 4e 8d 7f 57 8e 80 57 a9 00 a2 bf d0 04 a5 73 a6 74 85 80 86 81 a2 0c a9 40 20 ec 4e 20 08 58 2c 81 db dc 2c 81 db dc a9 96 a0 58 85 9b 84 9c a9 96 a0 58 85 96 84 97 a9 00 a0 d4 85 94 84 95 20 9a d3 2c 80 db dc 60 ad 00 bf c9 4c d0 0c ad ff bf c9 10 b0 02 09 10 8d 81 57 60 f3 57 7e 58 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c0
 FujiNet -> AppleWin  .  .  .  .  `  .  *  W  .  .  .  .  .  .  .  .  .  .  X  L  Y  W  `  .  .  .  .  .  .  W  .  .  .  .  .  .  .  .  .  .  W  .  .  .  .  .  .  .  .  L  .  .  .  o  .  .  .  .  .  .  .  .  N  .  .  W  .  .  W  .  .  .  .  .  .  .  s  .  t  .  .  .  .  .  .  .  @     .  N     .  X  ,  .  .  .  ,  .  .  .  .  .  .  X  .  .  .  .  .  .  .  X  .  .  .  .  .  .  .  .  .  .  .  .     .  .  ,  .  .  .  `  .  .  .  .  L  .  .  .  .  .  .  .  .  .  .  .  .  .  W  `  .  W  .  X  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 04 00 06 50 c0
AppleWin ->  FujiNet  .  .  .  .  P  .
 FujiNet -> AppleWin c0 04 00 25 31 16 0e c0
 FujiNet -> AppleWin  .  .  .  %  1  .  .  .
AppleWin ->  FujiNet c0 05 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 05 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 06 00 01 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 06 00 fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 30 20 20 01 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  0        .  @  .  .  .
AppleWin ->  FujiNet c0 07 00 02 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 07 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 31 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  1        .  @  .  .  .
AppleWin ->  FujiNet c0 08 00 03 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 08 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 32 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  2        .  @  .  .  .
AppleWin ->  FujiNet c0 09 00 04 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 09 00 ec 00 00 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53 4b 5f 33 20 20 02 40 01 0f c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  F  U  J  I  N  E  T  _  D  I  S  K  _  3        .  @  .  .  .
AppleWin ->  FujiNet c0 0a 00 05 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 0a 00 30 00 00 00 03 43 50 4d 20 20 20 20 20 20 20 20 20 20 20 20 20 12 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  C  P  M                                         .  .  .  .  .
AppleWin ->  FujiNet c0 0b 00 06 03 c0
AppleWin ->  FujiNet  .  .  .  .  .  .
 FujiNet -> AppleWin c0 0b 00 30 00 00 00 08 46 4e 5f 43 4c 4f 43 4b 20 20 20 20 20 20 20 20 13 00 00 01 c0
 FujiNet -> AppleWin  .  .  .  0  .  .  .  .  F  N  _  C  L  O  C  K                          .  .  .  .  .
AppleWin ->  FujiNet c0 0c 00 06 54 c0
AppleWin ->  FujiNet  .  .  .  .  T  .
 FujiNet -> AppleWin c0 0c 00 14 18 09 05 0e 16 14 c0
 FujiNet -> AppleWin  .  .  .  .  .  .  .  .  .  .  .
AppleWin ->  FujiNet c0 0d 00 06 50 c0
AppleWin ->  FujiNet  .  .  .  .  P  .
 FujiNet -> AppleWin c0 0d 00 25 31 16 0e c0
 FujiNet -> AppleWin  .  .  .  %  1  .  .  .
*/
