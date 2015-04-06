#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#define check_iface(ifname) (if_nametoindex((ifname)) != 0)

void main(int argc, char *argv[])
{
  int fd;

  if (argc != 2 || !check_iface(argv[1]))
  {
    fprintf(stderr, "Invalid interface name.\n");
    return;
  }

  if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
  {
    fprintf(stderr, "ERROR creating raw socket.\n");
    return;
  }

  if ((setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, argv[1], strlen(argv[1]))) == -1)
  {
    fprintf(stderr, "ERROR binding socket to device %s.\n", argv[1]);
    close(fd);
    return;
  }

  close(fd);
}
