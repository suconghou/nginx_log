## nim 版本

```
nim --mm:orc -d:release --passC:-flto --passL:-flto --passL:-s --passL:-static --opt:speed c main
nim --mm:arc -d:release --passC:-flto --passL:-flto --passL:-s --passL:-static --opt:speed c main
```

nim 使用 orc, arc 相比其他gc算法速度更快


## c 版本

```
gcc -std=c11 -static-libstdc++ -static-libgcc --static -Wl,-Bstatic,--gc-sections -O3 -ffunction-sections -fdata-sections main.c -o ngx_log
```


## c++ 版本

```
g++ -std=c++20 -static-libstdc++ -static-libgcc --static -Wl,-Bstatic,--gc-sections -O3 -ffunction-sections -fdata-sections main.cpp -o ngx_log

```

分析格式为nginx默认配置格式
```
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

```

非正则匹配，是基于字符分析的匹配，再此格式上后面补充也可正常分析

c版本速度最快，内存占用也最小，nim与c++版本速度相当，比c版本慢40%
