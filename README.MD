## nim 


去除所有set, in , 操作符 ； 比较性能



测试 add AppendStrCh 性能,以保证最后留有一个空格


 log_format vhosts '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for" '
                      '$host $request_length $bytes_sent $upstream_addr '
                      '$upstream_status $request_time $upstream_response_time '
                      '$upstream_connect_time $upstream_header_time';


266M log, 746110 line

refc 3.685

orc 2.536

arc 2.531

regions 3.944


nim 使用 orc, arc 速度更快

nim --mm:orc -d:release c main



TODO 优化排序算法

## c

gcc -O3 main.c

Os 1.955

O1 1.873

O2 1.425

O3 1.313


## c++

g++ -std=c++11 -Os main.cpp