±àÒë£º
gcc -o tcpclient tcp_client.c pub.h


Ö´ĞĞ£º
root@ubuntu:/home/xuyang/workspace/tcp_client# 
root@ubuntu:/home/xuyang/workspace/tcp_client# ./tcpclient 116.62.137.197
server ip 116.62.137.197
connected to server 116.62.137.197 OK
step 1 send OK, date len:312
^C
root@ubuntu:/home/xuyang/workspace/tcp_client# 
root@ubuntu:/home/xuyang/workspace/tcp_client# ./tcpclient 116.62.137.197
dadaoelectric.tpddns.cn -> 121.237.224.91
server ip 116.62.137.197
connected to server 116.62.137.197 OK
step 1 send OK, date len:312
step 1 receive OK, date len:312
step 2 send OK, date len:1080
step 2 receive OK, date len:1080
step 3 send OK, date len:1340
step 3 receive OK, date len:1340
step 4 send OK, date len:156
step 4 receive OK, date len:56
server quit, bye.
root@ubuntu:/home/xuyang/workspace/tcp_client# 