

import os, tables, sets, strformat, strutils, terminal, heapqueue


type Line = object
    index: int
    str: string
    l: int


# 类似内置substr的更快实现
func substr(s: string, first: int, last: int): string =
    let l = last-first+1
    if l < 1:
        return ""
    result = newString(l)
    copyMem(result[0].addr, cast[cstring](cast[uint](s.cstring)+first.uint), l)

# 根据条件匹配直至不满足条件，舍去前后空格
proc parse_item_trim_space(this: var Line, cond: proc): string =
    while this.index < this.l and this.str[this.index] == ' ':
        this.index+=1
    var i = this.index;
    var found_start = -1;
    var found_end = -1;
    var y = if likely(i > 0): this.str[i-1] else: '\0'
    while i < this.l:
        let x = this.str[i]
        i+=1; # i已指向下一个字符
        # 符合预定格式,x为当前字符,y为上个字符,可能为0
        if likely(cond(x, y)):
            y = x
            found_end = i-1
            if unlikely(found_start < 0):
                found_start = found_end
            # 如果未到行末尾,才能continue,否则i=len了,不能continue,会造成下次退出循环,item_value未赋值
            if i < this.l:
                continue
        # 否则匹配到边界或者完全没有匹配到
        if unlikely(found_start < 0):
            # 完全没有匹配到
            raise newException(ValueError, "匹配失败:"&this.str)
        while i < this.l and this.str[i] == ' ':
            i+=1
        this.index = i;
        # cond成立时,则包含当前字符x，否则不包含，截取的字符最少1字节
        return this.str.substr(found_start, found_end)
    raise newException(ValueError, "匹配失败:"&this.str)

proc parse_item_wrap_string(this: var Line, left: char = '"', right: char = '"'): string =
    while this.index < this.l and this.str[this.index] == '\32':
        this.index+=1
    if this.index >= this.l or this.str[this.index] != left:
        raise newException(ValueError, "匹配失败:"&this.str)
    this.index+=1
    let start = this.index
    let p = this.str.find(right, start)
    if p < start:
        raise newException(ValueError, "匹配失败:"&this.str)
    this.index = p+1
    return this.str.substr(start, p-1)


# 仅数字
proc digital(x: char, y: char): bool = x >= '\48' and x <= '\57'

# 包含数字和.号
proc digital_dot(x: char, y: char): bool = (x >= '\48' and x <= '\57') or x == '\46'

# 包含数字字母[a-f]和.号或:号（IPv4或IPv6）
proc digital_dot_colon(x: char, y: char): bool = (x >= '\48' and x <= '\58') or x == '\46' or (x >= '\97' and x <= '\102')

# 包含数字和.号或-号
proc digital_dot_minus(x: char, y: char): bool = (x >= '\48' and x <= '\57') or x == '\46' or x == '\45'

# 非空格
proc not_space(x: char, y: char): bool = x != '\32'

# 当前是空格，上一个是-或者数字
proc digital_or_none_end(x: char, y: char): bool = not (x == '\32' and ( (y >= '\48' and y <= '\57') or y == '\45'))

# 包含数字字母和.号或:号（IPv4或IPv6）
proc parse_remote_addr(this: var Line): string =
    return this.parse_item_trim_space(digital_dot_colon)

# 去除可能存在的-,非空格
proc parse_remote_user(this: var Line): string =
    while this.index < this.l and this.str[this.index] == '\45':
        this.index+=1
    return this.parse_item_trim_space(not_space)

# 匹配到],并且下一个是空格
proc parse_time_local(this: var Line): string =
    return this.parse_item_wrap_string('[', ']')

# 匹配到双引号结束位置
proc parse_request_line(this: var Line): string =
    return this.parse_item_wrap_string()

# 是数字
proc parse_status_code(this: var Line): string =
    return this.parse_item_trim_space(digital)

# 是数字
proc parse_body_bytes_sent(this: var Line): string =
    return this.parse_item_trim_space(digital)

# 匹配到双引号结束位置
proc parse_http_referer(this: var Line): string =
    return this.parse_item_wrap_string()

# 匹配到双引号结束位置
proc parse_http_user_agent(this: var Line): string =
    return this.parse_item_wrap_string()

# 匹配到双引号结束位置
proc parse_http_x_forwarded_for(this: var Line): string =
    return this.parse_item_wrap_string()

# 非空格的字符
proc parse_host(this: var Line): string =
    return this.parse_item_trim_space(not_space)

# 数字
proc parse_request_length(this: var Line): string =
    return this.parse_item_trim_space(digital)

# 数字
proc parse_bytes_sent(this: var Line): string =
    return this.parse_item_trim_space(digital)

# 非空格的字符
proc parse_upstream_addr(this: var Line): string =
    return this.parse_item_trim_space(not_space)

# 当前是空格，上一个是-或者数字
proc parse_upstream_status(this: var Line): string =
    return this.parse_item_trim_space(digital_or_none_end)

# 数字和.号
proc parse_request_time(this: var Line): string =
    return this.parse_item_trim_space(digital_dot)

# 数字和.号，或者-
proc parse_upstream_response_time(this: var Line): string =
    return this.parse_item_trim_space(digital_dot_minus)

# 数字和.号，或者-
proc parse_upstream_connect_time(this: var Line): string =
    return this.parse_item_trim_space(digital_dot_minus)

# 数字和.号，或者-
proc parse_upstream_header_time(this: var Line): string =
    return this.parse_item_trim_space(digital_dot_minus)

proc topK*[T](ct: CountTable[T], k: int): seq[(int, T)] =
    if k > 0:
        var h = initHeapQueue[(int, T)]()
        for key, count in ct.pairs:
            if h.len < k:
                h.push((count, key))
            elif count > h[0][0]:
                discard h.pop()
                h.push((count, key))
        result = newSeq[(int, T)](h.len)
        var i = h.len - 1
        while h.len > 0:
            result[i] = h.pop()
            i -= 1

proc process(filename: File|string) =
    var remote_addr_data = newCountTable[string](8192);
    var remote_user_data = newCountTable[string](64);
    var time_local_data = newCountTable[string](16384);
    var request_line_data = newCountTable[string](16384);
    var status_data = newCountTable[string](64);
    var http_referer_data = newCountTable[string](8192);
    var http_user_agent_data = newCountTable[string](8192);
    var http_x_forwarded_for_data = newCountTable[string](2048);
    var http_sent_data = newCountTable[string](16384);
    var http_bad_code_data = newOrderedTable[string, ref CountTable[string]]();
    var total_bytes_sent: uint64 = 0;
    var total_lines: uint = 0;


    proc parse_line(line: string) =
        var l = Line(str: line, l: line.len)
        let remote_addr = l.parse_remote_addr()
        let remote_user = l.parse_remote_user()
        let time_local = l.parse_time_local()
        let request_line = l.parse_request_line()
        let status_code = l.parse_status_code()
        let body_bytes_sent = l.parse_body_bytes_sent()
        let http_referer = l.parse_http_referer()
        let http_user_agent = l.parse_http_user_agent()
        let http_x_forwarded_for = l.parse_http_x_forwarded_for()


        let bytes_sent_num = parseUint(body_bytes_sent)

        total_bytes_sent+=bytes_sent_num

        remote_addr_data.inc(remote_addr)
        remote_user_data.inc(remote_user)
        time_local_data.inc(time_local)
        request_line_data.inc(request_line)
        status_data.inc(status_code)
        http_referer_data.inc(http_referer)
        http_user_agent_data.inc(http_user_agent)
        http_x_forwarded_for_data.inc(http_x_forwarded_for)
        http_sent_data.inc(request_line, bytes_sent_num.int)
        if status_code != "200":
            http_bad_code_data.mgetOrPut(status_code, newCountTable[string]()).inc(request_line)

    for line in filename.lines:
        try:
            parse_line(line);
            total_lines+=1;
        except Exception:
            stderr.writeLine(line)
    # 分析完毕后，排序然后，打印统计数据

    let str_sent = formatSize(total_bytes_sent.int64, prefix = bpColloquial, includeSpace = true)
    let ip_count = remote_addr_data.len
    echo &"\n共计\e[1;34m{total_lines}\e[00m次访问\n发送总流量\e[1;32m{str_sent}\e[00m\n独立IP数\e[1;31m{ip_count}\e[00m"
    if total_lines < 1:
        return
    let limit = 100;
    let t_width = terminalWidth() - 16
    let lines = total_lines.float
    let total_bytes = total_bytes_sent.float

    proc print_stat_long(name: string, data: ref CountTable[string]) =
        echo &"\n\e[1;34m{name}\e[00m"
        var n = 0;
        for (num, u) in data[].topK(limit):
            var stru = if u.len < t_width: u.alignLeft(t_width) else: u.substr(0, t_width-1)
            echo fmt"{stru} {num:>6.6} {num.float*100/lines:.2f}%"
            n+=num
        let part1 = (fmt"{n}/{total_lines}").alignLeft(t_width)
        echo &"前{limit}项占比\n{part1} {data.len:6.6} {n.float*100/lines:.2f}%\n"

    proc print_sent_long(name: string, data: ref CountTable[string]) =
        echo &"\n\e[1;34m{name}\e[00m"
        var n = 0;
        let max_width = t_width - 6
        for (num, u) in data[].topK(limit):
            var stru = if u.len < max_width: u.alignLeft(max_width) else: u.substr(0, max_width-1)
            echo fmt"{stru} {formatSize(num,prefix = bpColloquial, includeSpace = true):>12.12} {num.float*100/total_bytes:.2f}%"
            n+=num
        let part1 = (fmt"{formatSize(n,prefix = bpColloquial, includeSpace = true)}/{formatSize(total_bytes_sent.int64,prefix = bpColloquial, includeSpace = true)}").alignLeft(max_width)
        echo &"前{limit}项占比\n{part1} {data.len:12.12} {n.float*100/total_bytes:.2f}%\n"

    proc print_code_long(code: string, data: ref CountTable[string]) =
        var count = 0;
        for n in data.values:
            count+=n
        echo &"\n\e[1;34m状态码{code},共{count}次,占比{(count*100).float/lines:.2f}%\e[00m"
        var n = 0;
        for (num, u) in data[].topK(limit):
            var stru = if u.len < t_width: u.alignLeft(t_width) else: u.substr(0, t_width-1)
            echo fmt"{stru} {num:>6.6} {num.float*100/count.float:.2f}%"
            n+=num
        let part1 = (fmt"{n}/{count}").alignLeft(t_width)
        echo &"前{limit}项占比\n{part1} {data.len:6.6} {n.float*100/count.float:.2f}%\n"



    # 来访IP统计
    print_stat_long("来访IP统计", remote_addr_data)

    # 用户统计
    print_stat_long("用户统计", remote_user_data)

    # 代理IP统计
    print_stat_long("代理IP统计", http_x_forwarded_for_data)

    # HTTP请求统计
    print_stat_long("HTTP请求统计", request_line_data)

    # User-Agent统计
    print_stat_long("User-Agent统计", http_user_agent_data)

    # HTTP REFERER 统计
    print_stat_long("HTTP REFERER 统计", http_referer_data)

    # 请求时间
    print_stat_long("请求时间统计", time_local_data)

    # HTTP响应状态统计
    print_stat_long("HTTP响应状态统计", status_data)

    # HTTP流量占比统计
    print_sent_long("HTTP流量占比统计", http_sent_data)

    # 非200状态码
    http_bad_code_data.sort(proc (x, y: (string, ref CountTable[string])): int = cmp(x[0], y[0]))
    for code, items in http_bad_code_data:
        print_code_long(code, items)





try:
    if paramCount() > 0:
        process(paramStr(1))
    else:
        process(stdin)
except Exception:
    echo getCurrentExceptionMsg()
    quit(1)


