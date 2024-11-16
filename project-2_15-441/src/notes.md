\Maintain ssthresh on socket
//done: initiate to ssthresh=64 KB
Maintain "dup_acks" on the socket 
// done: Initiate dup_ack = 0
Maintain "cwin" (already)
 initiate cwnd = 1

Note: mind macro: "is_slow_start" = (cwnd < ssthresh)

Where acks/packet acks are received...
If "dup_acks" == 3
 set cwnd = ("is_slow_start" ? x2 : x.5) cwnd
 set ssthreshold  = cwnd
   Raphael - is on making that change seamless 
 fast recovery retransmit 
   resend specific packet seq number
   block e.g if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) <= 0) {}
   if default_timeout is hit 
       Set ssthresh = cwnd/2
       Set cwnd = 1
   if ack received 
         resend next expected sequence number (indicated by cummulative ack)
           "Note that when the retransmitted copy of packet 3 arrives at the destination, 
           the receiver then sends a cumulative ACK for everything up to and including / packet 6 back to the source."