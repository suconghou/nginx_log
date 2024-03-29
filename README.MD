## nim 版本

```
nim --mm:orc --threads:off --passC:-flto --passL:-flto -d:release --passL:-s --passL:-static --opt:speed c main
nim --mm:arc --threads:off --passC:-flto --passL:-flto -d:release --passL:-s --passL:-static --opt:speed c main
```

nim 使用 orc, arc 相比其他gc算法速度更快

注意本地测试时也要threads:off,编译出来的性能略有提升

```
nim --threads:off --mm:arc -d:release --opt:speed c main.nim
```


## c 版本

```
gcc -Wall -std=c17 -flto=auto -static-libstdc++ -static-libgcc --static -Wl,-Bstatic,--gc-sections -O3 -ffunction-sections -fdata-sections main.c -o ngx_log
```


## c++ 版本

```
g++ -Wall -std=c++20 -flto=auto -static-libstdc++ -static-libgcc --static -Wl,-Bstatic,--gc-sections -O3 -ffunction-sections -fdata-sections main.cpp -o ngx_log

```

分析格式为nginx默认配置格式
```
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

```

非正则匹配，是基于字符分析的匹配，再此格式上后面补充也可正常分析

c版本速度最快，内存占用也最小，nim与c++版本速度相当，比c版本慢40%

测试数据700MB+, 约200万行

| 版本  | 时间  |
| ------ | ------   |
| c     | 1.932s    |
| c++   | 6.086s    |
| nim   | 5.698s    |




