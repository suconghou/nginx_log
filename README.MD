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


## zig 版本

```
# 本机编译 (macOS / Linux)
zig build-exe main.zig -O ReleaseFast -fstrip

# 静态交叉编译 Linux 二进制 (musl 静态链接, 部署无运行时依赖)
zig build-exe main.zig -O ReleaseFast -target x86_64-linux-musl -lc -fstrip -femit-bin=bin/nginx_log_linux_x86_64
zig build-exe main.zig -O ReleaseFast -target aarch64-linux-musl -lc -fstrip -femit-bin=bin/nginx_log_linux_aarch64
```

超 1G 的日志走 512MB 窗口 mmap, 每解析完一个窗口立即 munmap 归还物理页, 内存占用恒定, 6G+ 文件也不会 OOM; 解析当前窗口前异步预读下一窗口, 磁盘 I/O 与解析重叠

支持 `./main access.log` 与 `zcat access.log*.gz | ./main` 两种用法, stdin 会转存到磁盘临时文件再按窗口映射, 不占内存


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




