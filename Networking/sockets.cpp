
#include "sockets.h"
#include "Tools/Exceptions.h"
#include "Tools/time-func.h"
#include "Processor/OnlineOptions.h"

#include <iostream>
#include <fcntl.h>
using namespace std;

void error(const char *str, bool interrupted, size_t length)
{
  int old_errno = errno;
  char err[1000];
  gethostname(err, 1000);
  err[999] = 0;
  string message = string() + "Fatal communication error on " + err + ": "
      + str + " (" + strerror(old_errno) + ")";
  if (length)
    message += " when sending " + to_string(length) + " bytes";
  if (interrupted)
    message += "\nThis is probably because another party encountered a problem.";
  exit_error(message);
}

void set_up_client_socket(int& mysocket,const char* hostname,int Portnum)
{
   struct addrinfo hints, *ai=NULL,*rp;
   memset (&hints, 0, sizeof(hints));
   hints.ai_family = AF_INET;
   hints.ai_flags = AI_CANONNAME;

   char my_name[512];
   memset(my_name,0,512*sizeof(octet));
   gethostname((char*)my_name,512);

   int erp;
   for (int i = 0; i < CONNECTION_TIMEOUT; i++)
     { erp=getaddrinfo (hostname, NULL, &hints, &ai);
       if (erp == 0)
         { break; }
       else
         { cerr << "getaddrinfo on " << my_name << " has returned '" << gai_strerror(erp) <<
           "' for " << hostname << ", trying again in a second ..." << endl;
           if (ai)
             freeaddrinfo(ai);
           sleep(1);
         }
     }
   if (erp!=0)
     { error("set_up_socket:getaddrinfo");  }

   bool success = false;
   socklen_t len = 0;
   const struct sockaddr* addr = 0;
   for (rp=ai; rp!=NULL; rp=rp->ai_next)
      { addr = ai->ai_addr;

        if (ai->ai_family == AF_INET)
           {
             len = ai->ai_addrlen;
             success = true;
             continue;
           }
      }

   if (not success)
     {
       for (rp = ai; rp != NULL; rp = rp->ai_next)
         cerr << "Family on offer: " << ai->ai_family << endl;
       exit_error(string("No AF_INET for ") + (char*)hostname + " on " + (char*)my_name);
     }


   Timer timer;
   timer.start();
   struct sockaddr_in* addr4 = (sockaddr_in*) addr;
   addr4->sin_port = htons(Portnum);      // set destination port number
#ifdef DEBUG_IPV4
   cout << "connect to ip " << hex << addr4->sin_addr.s_addr << " port " << addr4->sin_port << dec << endl;
#endif

   int attempts = 0;
   long wait = 1;
   int fl;
   int connect_errno;
   do
   {
       mysocket = socket(AF_INET, SOCK_STREAM, 0);
       if (mysocket < 0)
         error("set_up_socket:socket");

       fl = connect(mysocket, addr, len);
       connect_errno = errno;
       attempts++;
       if (fl != 0)
         {
           close(mysocket);
           usleep(wait < 1000 ? wait *= 2 : wait);
           if (OnlineOptions::singleton.has_option("debug_networking"))
            {
              string msg = "Connecting to " + string(hostname) + ":"
                  + to_string(Portnum) + " failed";
              errno = connect_errno;
              perror(msg.c_str());
            }
         }
       errno = connect_errno;
   }
   while (fl == -1 &&
    (errno == ECONNREFUSED || errno == ETIMEDOUT || errno == EINPROGRESS || errno == ECONNRESET) &&
    timer.elapsed() < CONNECTION_TIMEOUT);

   if (fl < 0)
     {
       exit_error(
           string() + "cannot connect from " + my_name + " to " + hostname + ":"
               + to_string(Portnum) + " after " + to_string(attempts)
               + " attempts in " + to_string(CONNECTION_TIMEOUT)
               + " seconds because " + strerror(connect_errno) + ". "
               "https://mp-spdz.readthedocs.io/en/latest/troubleshooting.html#"
               "connection-failures has more information on port requirements.");
     }

   freeaddrinfo(ai);

   if (OnlineOptions::singleton.has_option("time_connect"))
     cerr << "Connection took " << timer.elapsed() << " seconds." << endl;

  /* disable Nagle's algorithm */
  int one=1;
  fl= setsockopt(mysocket, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(int));
  if (fl<0) { error("set_up_socket:setsockopt");  }
    

  /* 
  * The following code block is either taken directly from or derived from the solutions posted at:
  *     https://stackoverflow.com/questions/20188718/configuring-tcp-keep-alive-with-boostasio
  *     https://stackoverflow.com/questions/23669005/tcp-keepalive-protocol-not-available
  */
  unsigned int timeout_milli = 10000;

  #if (defined _WIN32 || defined WIN32 || defined OS_WIN64 || defined _WIN64 || defined WIN64 || defined WINNT)
    int32_t timeout = timeout_milli;
    fl = setsockopt(mysocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    if (fl<0) { error("set_tcp_keepalive:setsockopt(SOL_SOCKET, SO_RCVTIMEO)");  }

    fl = setsockopt(mysocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    if (fl<0) { error("set_tcp_keepalive:setsockopt(SOL_SOCKET, SO_SNDTIMEO)");  }

  #else
    struct timeval tv;
    tv.tv_sec  = timeout_milli / 1000;
    tv.tv_usec = (timeout_milli % 1000) * 1000;

    fl = setsockopt(mysocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (fl<0) { error("set_tcp_keepalive:setsockopt(SOL_SOCKET, SO_RCVTIMEO)");  }

    fl = setsockopt(mysocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (fl<0) { error("set_tcp_keepalive:setsockopt(SOL_SOCKET, SO_RCVTIMEO)");  }

    int enable_keepalive = 1;
    int keepalive_strobe_interval_secs = 3;
    int num_keepalive_strobes = 5;

    fl = setsockopt(mysocket, SOL_SOCKET, SO_KEEPALIVE,(char *)&enable_keepalive, sizeof(enable_keepalive));
    if (fl<0) { error("set_tcp_keepalive:setsockopt(SOL_SOCKET, SO_KEEPALIVE)");  }

    #ifdef TCP_KEEPIDLE
      int keepalive_idle_time_secs = 1;
      fl = setsockopt(mysocket, IPPROTO_TCP, TCP_KEEPIDLE, (char *)&keepalive_idle_time_secs, sizeof(keepalive_idle_time_secs));
      if (fl<0) { error("set_tcp_keepalive:setsockopt(IPPROTO_TCP, TCP_KEEPIDLE)");  }
    #endif

    fl = setsockopt(mysocket, IPPROTO_TCP, TCP_KEEPINTVL, (char *)&keepalive_strobe_interval_secs, sizeof(keepalive_strobe_interval_secs));
    if (fl<0) { error("set_tcp_keepalive:setsockopt(IPPROTO_TCP, TCP_KEEPINTVL)");  }

    setsockopt(mysocket, IPPROTO_TCP, TCP_KEEPCNT, (char *)&num_keepalive_strobes, sizeof(num_keepalive_strobes));
    if (fl<0) { error("set_tcp_keepalive:setsockopt(IPPROTO_TCP, TCP_KEEPCNT)");  }

  #endif
  /* End third-party code */

#ifdef __APPLE__
  int flags = fcntl(mysocket, F_GETFL, 0);
  fl = fcntl(mysocket, F_SETFL, O_NONBLOCK |  flags);
  if (fl < 0)
    error("set non-blocking on client");
#endif
}

void close_client_socket(int socket)
{
  if (close(socket))
    {
      char tmp[1000];
      snprintf(tmp, 1000, "close(%d)", socket);
      error(tmp);
    }
}

void send(int socket, octet* msg, size_t len)
{
  size_t i = 0;
  long wait = 1;
  long count = 0;
  long max_wait = 0;

  while (i < len)
    {
      count++;
      size_t j = send_non_blocking(socket, msg + i, len - i);
      i += j;
      if (j > 0)
        wait = 1;
      else
        {
          max_wait = max(wait, max_wait);
          usleep(wait);
          wait *= 2;
          wait = min(wait, 1000l);
        }
    }

  if (OnlineOptions::singleton.has_option("send_count"))
    if (max_wait)
      fprintf(stderr, "called send %ld times, maximum wait %e seconds\n", count,
          max_wait * 1e-6);
}

void receive(int socket, octet* msg, size_t len)
{
  size_t i = 0;
  int fail = 0;
  long wait = 1;
  long count = 0;
  long max_wait = 0;

  while (len - i > 0)
    {
      int j = recv(socket, msg + i, len - i, 0);
      count++;

      // success first
      if (j > 0)
        {
          i = i + j;
          fail = 0;
          wait = 1;
        }
      else if (j < 0)
        {
          if (errno == EAGAIN or errno == EINTR)
            {
              if (++fail > 100000)
                error("Unavailable too many times", true);
              else
                {
                  wait = min(wait, 500l);
                  usleep(wait *= 2);
                  max_wait = max(wait, max_wait);
                }
            }
          else
            {
              error("Receiving error", true, len - i);
            }
        }
      else
        throw closed_connection();
    }

  if (max_wait and OnlineOptions::singleton.has_option("recv_count"))
    fprintf(stderr, "called recv %ld times, maximum wait %e seconds\n", count,
        max_wait * 1e-6);
}
