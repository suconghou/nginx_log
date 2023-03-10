

import os, tables, sets, strformat, strutils, terminal


type Line = object
    index: int
    str: string

const blank = {' '}
const quotation = {'"'}
const square_left = {' ', '['}
const square_right = {' ', ']'}

# 根据条件解析，并去除前置后置x字符
proc parse_item_trimx(this: var Line, left: set[char], right: set[char], cond: proc, strip_left: set[char] = {}): string =
    let strlen = this.str.len;
    var i = this.index;
    var item_value: string;
    var pad = true;
    var found_start = -1;
    var found_end = -1;
    while i < strlen:
        let x = this.str[i]
        i+=1; # i已指向下一个字符
        if x in left and pad:
            # 去前置连续x
            this.index = i;
            continue
        else:
            pad = false
        if item_value.len < 1:
            let y = if i < strlen: this.str[i] else: '\x00'
            let z = if i >= 2: this.str[i-2] else: '\x00'
            # 符合预定格式,x为当前字符,y为下个字符,y可能为0,z为上一个字符
            if cond(x, y, z):
                found_end = i-1
                if found_start < 0:
                    found_start = found_end
                # 如果未到行末尾,才能continue,否则i=len了,不能continue,会造成下次退出循环,item_value未赋值
                if i < strlen:
                    continue
            # 否则匹配到边界或者完全没有匹配到
            if found_start < 0:
                # 完全没有匹配到
                raise newException(ValueError, "匹配失败:"&this.str)
            # 包含cond成立时当前字符x,如果结果字符串以某字符开始，我们配置了strip_left开头
            # 例如解析request_line,开头有引号,我们仅在生成结果时过滤
            if strip_left.len > 0:
                while found_start < found_end:
                    if this.str[found_start] in strip_left:
                        found_start+=1
                    else:
                        break;
            item_value = this.str.substr(found_start, found_end)
            # 执行到此处，已匹配到了想要的字符串，要么匹配到字符串结尾了，要么中途中断，要么匹配到最后一个字符了但不符合
            if i >= strlen:
                # 如果中途中断，则不会进入此条件，下次循环会进去后置特定字符逻辑
                # 如果最后一个字符符合，则found=len-1,此时剩余应为空
                # 如果最后一个字符不符合，判断是否是后置字符，如果是则也为空
                if found_end == strlen-1 or x in right:
                    this.index = strlen-1
                else:
                    this.index = found_end+1
        else:
            if x in right:
                # 去后置特定字符,如果当前字符就是最后一个字符，并且当前字符是特定字符，则i需等于len,以完全裁剪
                if i < strlen:
                    continue;
                elif i == strlen:
                    i+=1
            this.index = i-1
            break
    # 防止前置字符去除时，直接continue完所有
    if item_value.len < 1:
        raise newException(ValueError, "匹配失败:"&this.str)
    return item_value

# 仅数字
proc digital(x: char, y: char, z: char): bool = x >= '\48' and x <= '\57'

# 包含数字和.号
proc digital_dot(x: char, y: char, z: char): bool = (x >= '\48' and x <= '\57') or x == '\46'

# 包含数字字母和.号或:号（IPv4或IPv6）
proc digital_dot_colon(x: char, y: char, z: char): bool = (x >= '\48' and x <= '\58') or x == '\46' or (x >= '\97' and x <= '\122')

# 包含数字和.号或-号
proc digital_dot_minus(x: char, y: char, z: char): bool = (x >= '\48' and x <= '\57') or x == '\46' or x == '\45'

# 匹配到],并且下一个是空格
proc square_right_space(x: char, y: char, z: char): bool = not (x == '\93' and y == '\32')

# 非空格
proc not_space(x: char, y: char, z: char): bool = x != '\32'

# 包含2个双引号，匹配到第二个双引号结束
proc quote_string_end(): proc =
    var q = 0;
    return proc (x: char, y: char, z: char): bool =
        if x == '\34':
            q+=1
        if (x == '\34' and q == 2):
            return false
        return true

# 当前字符是空格，上个字符是字母,不包含空格
proc string_end(x: char, y: char, z: char): bool = not (x == '\32' and ( (z >= '\65' and z <= '\90') or (z >= '\97' and z <= '\122')))

# 当前是空格，上一个是-或者数字
proc digital_or_none_end(x: char, y: char, z: char): bool = not (x == '\32' and ( (z >= '\48' and z <= '\57') or z == '\45'))

# 包含数字字母和.号或:号（IPv4或IPv6）
proc parse_remote_addr(this: var Line): string =
    return this.parse_item_trimx(blank, blank, digital_dot_colon)

# 去除可能存在的-,非空格
proc parse_remote_user(this: var Line): string =
    let strlen = this.str.len
    while this.index < strlen:
        if this.str[this.index] == '\45':
            this.index+=1
        else:
            break;
    return this.parse_item_trimx(blank, blank, not_space)

# 匹配到],并且下一个是空格
proc parse_time_local(this: var Line): string =
    return this.parse_item_trimx(square_left, square_right, square_right_space)

# 当前字符是双引号，下个字符是空格，上个字符是http版本,并且只能包含2个空格
proc parse_request_line(this: var Line): string =
    var c = 0;
    proc v(x: char, y: char, z: char): bool =
        if x == '\32':
            c+=1
        if c > 2:
            return false
        return not (x == '\34' and y == '\32' and (z == '\49' or z == '\48'))
    return this.parse_item_trimx(blank, blank, v, quotation)

# 是数字
proc parse_status_code(this: var Line): string =
    return this.parse_item_trimx(blank, blank, digital)

# 是数字
proc parse_body_bytes_sent(this: var Line): string =
    return this.parse_item_trimx(blank, blank, digital)

# 当前字符是双引号，下个字符是空格
proc parse_http_referer(this: var Line): string =
    return this.parse_item_trimx(blank, blank, quote_string_end(), quotation)

# 当前字符是双引号，下个字符是空格
proc parse_http_user_agent(this: var Line): string =
    return this.parse_item_trimx(blank, blank, quote_string_end(), quotation)

# 当前字符是双引号，下个字符是空格
proc parse_http_x_forwarded_for(this: var Line): string =
    return this.parse_item_trimx(blank, blank, quote_string_end(), quotation)

# 当前字符是空格，上个字符是字母
proc parse_host(this: var Line): string =
    return this.parse_item_trimx(blank, blank, string_end)

# 数字
proc parse_request_length(this: var Line): string =
    return this.parse_item_trimx(blank, blank, digital)

# 数字
proc parse_bytes_sent(this: var Line): string =
    return this.parse_item_trimx(blank, blank, digital)

# 当前是空格，上一个是-或者数字
proc parse_upstream_addr(this: var Line): string =
    return this.parse_item_trimx(blank, blank, digital_or_none_end)

# 当前是空格，上一个是-或者数字
proc parse_upstream_status(this: var Line): string =
    return this.parse_item_trimx(blank, blank, digital_or_none_end)

# 数字和.号
proc parse_request_time(this: var Line): string =
    return this.parse_item_trimx(blank, blank, digital_dot)

# 数字和.号，或者-
proc parse_upstream_response_time(this: var Line): string =
    return this.parse_item_trimx(blank, blank, digital_dot_minus)

# 数字和.号，或者-
proc parse_upstream_connect_time(this: var Line): string =
    return this.parse_item_trimx(blank, blank, digital_dot_minus)

# 数字和.号，或者-
proc parse_upstream_header_time(this: var Line): string =
    return this.parse_item_trimx(blank, blank, digital_dot_minus)




proc process(filename: File|string) =
    var remote_addr_data: OrderedTable[string, int];
    var remote_user_data: OrderedTable[string, int];
    var time_local_data: OrderedTable[string, int];
    var request_line_data: OrderedTable[string, int];
    var status_data: OrderedTable[string, int];
    var http_referer_data: OrderedTable[string, int];
    var http_user_agent_data: OrderedTable[string, int];
    var http_x_forwarded_for_data: OrderedTable[string, int];
    var http_sent_data: OrderedTable[string, int];
    var http_bad_code_data: OrderedTable[string, ref OrderedTable[string, int]];
    var total_bytes_sent: uint64 = 0;
    var total_lines: uint = 0;


    proc parse_line(line: string) =
        var l = Line(str: line)
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


        var n = remote_addr_data.getOrDefault(remote_addr, 0)
        remote_addr_data[remote_addr] = n+1
        n = remote_user_data.getOrDefault(remote_user, 0)
        remote_user_data[remote_user] = n+1
        n = time_local_data.getOrDefault(time_local, 0)
        time_local_data[time_local] = n+1
        n = request_line_data.getOrDefault(request_line, 0)
        request_line_data[request_line] = n+1
        n = status_data.getOrDefault(status_code, 0)
        status_data[status_code] = n+1
        n = http_referer_data.getOrDefault(http_referer, 0)
        http_referer_data[http_referer] = n+1
        n = http_user_agent_data.getOrDefault(http_user_agent, 0)
        http_user_agent_data[http_user_agent] = n+1
        n = http_x_forwarded_for_data.getOrDefault(http_x_forwarded_for, 0)
        http_x_forwarded_for_data[http_x_forwarded_for] = n+1
        n = http_sent_data.getOrDefault(request_line, 0)
        http_sent_data[request_line] = n+bytes_sent_num.int

        if status_code != "200":
            var info = http_bad_code_data.getOrDefault(status_code, newOrderedTable[string, int]())
            n = info.getOrDefault(request_line, 0)
            info[request_line] = n+1
            http_bad_code_data[status_code] = info

    for line in filename.lines:
        try:
            parse_line(line);
            total_lines+=1;
        except:
            stderr.writeLine(line)
    # 分析完毕后，排序然后，打印统计数据
    if total_lines < 1:
        return

    let str_sent = formatSize(total_bytes_sent.int64)
    let ip_count = remote_addr_data.len
    echo &"\n共计\e[1;34m{total_lines}\e[00m次访问\n发送总流量\e[1;32m{str_sent}\e[00m\n独立IP数\e[1;31m{ip_count}\e[00m"

    let limit = 100;
    let t_width = terminalWidth() - 16
    let lines = total_lines.float
    let total_bytes = total_bytes_sent.float

    proc print_stat_long(name: string, data: var OrderedTable[string, int]) =
        data.sort(proc (x, y: (string, int)): int = y[1]-x[1])
        echo &"\n\e[1;34m{name}\e[00m"
        var i = 0;
        var n = 0;
        for u, num in data:
            var stru = u
            if stru.len < t_width:
                stru = stru.alignLeft(t_width)
            else:
                stru = stru.substr(0, t_width-1)
            echo fmt"{stru} {num:>6.6} {num.float*100/lines:.2f}%"
            i+=1
            n+=num
            if i >= limit:
                break
        let part1 = (fmt"{n}/{total_lines}").alignLeft(t_width)
        echo &"前{limit}项占比\n{part1} {data.len:6.6} {n.float*100/lines:.2f}%\n"

    proc print_sent_long(name: string, data: var OrderedTable[string, int]) =
        data.sort(proc (x, y: (string, int)): int = y[1]-x[1])
        echo &"\n\e[1;34m{name}\e[00m"
        var i = 0;
        var n = 0;
        let max_width = t_width - 6
        for u, num in data:
            var stru = u
            if stru.len < max_width:
                stru = stru.alignLeft(max_width)
            else:
                stru = stru.substr(0, max_width-1)
            echo fmt"{stru} {formatSize(num):>12.12} {num.float*100/total_bytes:.2f}%"
            i+=1
            n+=num
            if i >= limit:
                break
        let part1 = (fmt"{formatSize(n)}/{formatSize(total_bytes_sent.int64)}").alignLeft(max_width)
        echo &"前{limit}项占比\n{part1} {data.len:12.12} {n.float*100/total_bytes:.2f}%\n"

    proc print_code_long(code: string, data: ref OrderedTable[string, int]) =
        data.sort(proc (x, y: (string, int)): int = y[1]-x[1])
        var count = 0;
        for n in data.values:
            count+=n
        echo &"\n\e[1;34m状态码{code},共{count}次\e[00m"
        var i = 0;
        var n = 0;
        for u, num in data:
            var stru = u
            if stru.len < t_width:
                stru = stru.alignLeft(t_width)
            else:
                stru = stru.substr(0, t_width-1)
            echo fmt"{stru} {num:>6.6} {num.float*100/lines:.2f}%"
            i+=1
            n+=num
            if i >= limit:
                break
        let part1 = (fmt"{n}/{total_lines}").alignLeft(t_width)
        echo &"前{limit}项占比\n{part1} {data.len:6.6} {n.float*100/lines:.2f}%\n"



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
    http_bad_code_data.sort(proc (x, y: (string, ref OrderedTable[string,
            int])): int = cmp(x[0], y[0]))
    for code, items in http_bad_code_data:
        print_code_long(code, items)





try:
    if paramCount() > 0:
        process(paramStr(1))
    else:
        process(stdin)
except:
    echo getCurrentExceptionMsg()
    quit(1)



runnableExamples:

    proc test1(line: string) =
        var l = Line(str: line)
        let remote_addr = l.parse_remote_addr()
        # echo "remote_addr:["&remote_addr&"]"
        # echo l.str
        let remote_user = l.parse_remote_user()
        # echo "remote_user:["&remote_user&"]"
        # echo l.str
        let time_local = l.parse_time_local()
        # echo "time_local:["&time_local&"]"
        # echo l.str
        let request_line = l.parse_request_line()
        # echo request_line
        # echo "request_line:["&request_line&"]"
        # echo l.str
        let status_code = l.parse_status_code()
        # echo "status_code:["&status_code&"]"
        # echo l.str

        let body_bytes_sent = l.parse_body_bytes_sent()
        # echo body_bytes_sent
        # echo "body_bytes_sent:["&body_bytes_sent&"]"
        # echo l.str

        let http_referer = l.parse_http_referer()
        # echo "http_referer:["&http_referer&"]"
        # echo l.str

        let http_user_agent = l.parse_http_user_agent()
        # echo http_user_agent
        # echo "http_user_agent:["&http_user_agent&"]"
        # echo l.str

        let http_x_forwarded_for = l.parse_http_x_forwarded_for()
        # echo "http_x_forwarded_for:["&http_x_forwarded_for&"]"
        # echo l.str


        # let host = l.parse_host()
        # echo "host:["&host&"]"
        # echo l.str

        # let request_length = l.parse_request_length()
        # echo request_length
        # echo "request_length:["&request_length&"]"
        # echo l.str

        # let bytes_sent = l.parse_bytes_sent()
        # echo "bytes_sent:["&bytes_sent&"]"
        # echo l.str

        # let upstream_addr = l.parse_upstream_addr()
        # echo "upstream_addr:["&upstream_addr&"]"
        # echo l.str

        # let upstream_status = l.parse_upstream_status()
        # echo "upstream_status:["&upstream_status&"]"
        # echo l.str

        # let request_time = l.parse_request_time()
        # echo "request_time:["&request_time&"]"
        # echo l.str


        # let upstream_response_time = l.parse_upstream_response_time()
        # echo "["&upstream_response_time&"]"
        # echo l.str



        # let upstream_connect_time = l.parse_upstream_connect_time()
        # echo "[upstream_connect_time:"&upstream_connect_time&"]"
        # echo l.str


        # let upstream_header_time = l.parse_upstream_header_time()
        # echo "[upstream_header_time:"&upstream_header_time&"]"
        # echo l.str

    for line in stdin.lines:
        try:
            test1(line)
        except:
            raise
            stderr.writeLine(getCurrentExceptionMsg())
            stderr.writeLine(line)

