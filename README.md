# EnhancedPing
Sends a ping to provided websites and processes returning packets concurrently. Measures hops and RTT of each ping.

Targets.txt - text file with target websites.

This python script does require root access.

Output will occurr when probing packets are sent to websites, when ICMP packets are matched, and when receive socket times out.

Several external sources were used when researching this project, the URLs listed below are specifically websites with code that I read and/or reused in my project.

Professor Michael Rabinovich - Building payload, probe packet, and sending probe packet to an address

Professor Michael Rabinovich - Converting a timestamp into a format that worked with the IPID field in the IP header

Professor Michael Rabinovich - Specific type of socket used for both sending and receiving sockets 

https://www.binarytides.com/raw-socket-programming-in-python-linux - Creation of ip header, creation of a raw socket

https://stackoverflow.com/questions/15049143/raw-socket-programming-udp-python - Creation of a udp header

https://gist.github.com/gabrielfalcao/20e567e188f588b65ba2 - Finding random port for source port of probing packets

