#include <string>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <array>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include <sys/ioctl.h> // ioctl() and TIOCGWINSZ
#include <unistd.h>    // for STDOUT_FILENO

typedef std::unordered_map<std::string, int> strMap;
typedef std::unordered_map<std::string, strMap> statusMap;
typedef std::pair<int, std::string> intstr;
typedef std::pair<std::string, strMap> strstrMap;

typedef bool (*char_is_match)(unsigned char x, unsigned char y);

// 仅数字
bool digital(unsigned char x, unsigned char y)
{
    return x >= 48 && x <= 57;
}

// 包含数字和.号
bool digital_dot(unsigned char x, unsigned char y)
{
    return (x >= 48 && x <= 57) || x == 46;
}

// 包含数字字母[a-f]和.号或:号（IPv4或IPv6）
bool digital_dot_colon(unsigned char x, unsigned char y)
{
    return (x >= 48 && x <= 58) || x == 46 || (x >= 97 && x <= 102);
}

// 包含数字和.号或-号
bool digital_dot_minus(unsigned char x, unsigned char y)
{
    return (x >= 48 && x <= 57) || x == 46 || x == 45;
}

// 非空格
bool not_space(unsigned char x, unsigned char y)
{
    return x != 32;
}

// 当前是空格，上一个是-或者数字
bool digital_or_none_end(unsigned char x, unsigned char y)
{
    return !(x == 32 && ((y >= 48 && y <= 57) || y == 45));
}

class Line
{
private:
    const char *ptr;       // 当前处理位置的指针
    const char *const str; // 字符串起始位置
    const char *const end; // 字符串结束位置的指针

    int parse_item_trim_space(char *item_value, const char_is_match cond)
    {
        while (ptr < end && *ptr == ' ')
        {
            ++ptr;
        }
        const char *found_start = nullptr;
        const char *found_end = nullptr;
        unsigned char y = (ptr > str) ? *(ptr - 1) : 0;
        while (ptr < end)
        {
            unsigned char x = *ptr++;
            if (cond(x, y))
            {
                found_end = ptr - 1;
                if (!found_start)
                {
                    found_start = found_end;
                }
                if (ptr < end)
                {
                    y = x;
                    continue;
                }
            }
            if (!found_start)
            {
                return -1;
            }
            // cond成立时,则包含当前字符x，否则不包含，截取的字符最少1字节
            const int v_len = found_end - found_start + 1;
            memcpy(item_value, found_start, v_len);
            item_value[v_len] = '\0';
            while (ptr < end && *ptr == ' ')
            {
                ++ptr;
            }
            return found_start - str;
        }
        return found_start ? (found_start - str) : -1;
    }

    int parse_item_wrap_string(char *item_value, const char &left = '"', const char &right = '"')
    {
        while (ptr < end && *ptr == ' ')
        {
            ++ptr;
        }
        if (ptr >= end || *ptr != left)
        {
            return -1;
        }
        ++ptr;
        const char *p = static_cast<const char *>(memchr(ptr, right, end - ptr));
        if (!p)
        {
            return -1;
        }
        const int v_len = p - ptr;
        memcpy(item_value, ptr, v_len);
        item_value[v_len] = '\0';
        ptr = p + 1;
        return 1;
    }

public:
    Line(char const *str);

    int parse_remote_addr(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_dot_colon);
    }

    int parse_remote_user(char *item_value)
    {
        while (ptr < end && *ptr == '-')
        {
            ++ptr;
        }
        return parse_item_trim_space(item_value, not_space);
    }

    int parse_time_local(char *item_value)
    {
        return parse_item_wrap_string(item_value, '[', ']');
    }

    int parse_request_line(char *item_value)
    {
        return parse_item_wrap_string(item_value);
    }

    int parse_status_code(char *item_value)
    {
        return parse_item_trim_space(item_value, digital);
    }

    int parse_body_bytes_sent(char *item_value)
    {
        return parse_item_trim_space(item_value, digital);
    }

    int parse_http_referer(char *item_value)
    {
        return parse_item_wrap_string(item_value);
    }

    int parse_http_user_agent(char *item_value)
    {
        return parse_item_wrap_string(item_value);
    }

    int parse_http_x_forwarded_for(char *item_value)
    {
        return parse_item_wrap_string(item_value);
    }

    int parse_host(char *item_value)
    {
        return parse_item_trim_space(item_value, not_space);
    }

    int parse_request_length(char *item_value)
    {
        return parse_item_trim_space(item_value, digital);
    }

    int parse_bytes_sent(char *item_value)
    {
        return parse_item_trim_space(item_value, digital);
    }

    int parse_upstream_addr(char *item_value)
    {
        return parse_item_trim_space(item_value, not_space);
    }

    int parse_upstream_status(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_or_none_end);
    }

    int parse_request_time(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_dot);
    }

    int parse_upstream_response_time(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_dot_minus);
    }

    int parse_upstream_connect_time(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_dot_minus);
    }

    int parse_upstream_header_time(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_dot_minus);
    }
};

Line::Line(const char *const line) : ptr(line), str(line), end(line + strlen(line))
{
}

// out 空间至少有32字节
static inline void byteFormat(unsigned long s, char *out)
{
    char const *unit = "KMGTPEZY";
    if (s < 1024)
    {
        snprintf(out, 32, "%lu B", s);
        return;
    }
    unit--;
    double n = (double)s;
    while (n >= 1024)
    {
        n /= 1024;
        unit++;
    }
    snprintf(out, 32, "%.2f %cB", n, *unit);
}

intstr *sort_map(const strMap &m) noexcept
{
    int i = 0;
    int l = m.size();
    auto arr = new intstr[l];
    for (const auto &[a, b] : m)
    {
        arr[i] = std::make_pair(b, a);
        i++;
    }
    int n = l > 100 ? 100 : l;
    std::partial_sort(arr, arr + n, arr + l, std::greater<>());
    return arr;
}

static inline int cmp(const strstrMap &a, const strstrMap &b) noexcept
{
    return a.first < b.first;
}

// pair 默认对first升序，当first相同时对second升序；
// 我们的second无法比较，需要自定义cmp函数
strstrMap *sort_strmap(const statusMap &m) noexcept
{
    int i = 0;
    auto arr = new strstrMap[m.size()];
    for (const auto &[a, b] : m)
    {
        arr[i] = std::make_pair(a, b);
        i++;
    }
    std::sort(arr, arr + m.size(), cmp);
    return arr;
}

int get_width()
{
    struct winsize size;
    char fds[3] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
    for (unsigned int fd = 0; fd < sizeof(fds) / sizeof(fds[0]); fd++)
    {
        if (ioctl(fd, TIOCGWINSZ, &size) != -1)
        {
            break;
        }
    }
    return size.ws_col;
}

int process(std::istream &fh)
{
    char str[8192] = {0};
    char value[8192] = {0}; // 后面多处使用此内存池复用
    unsigned long total_bytes_sent = 0;
    unsigned int total_lines = 0;

    strMap remote_addr_data;
    remote_addr_data.reserve(8192);
    strMap remote_user_data;
    remote_user_data.reserve(64);
    strMap time_local_data;
    time_local_data.reserve(16384);
    strMap request_line_data;
    request_line_data.reserve(16384);
    strMap status_data;
    status_data.reserve(64);
    strMap http_referer_data;
    http_referer_data.reserve(8192);
    strMap http_user_agent_data;
    http_user_agent_data.reserve(8192);
    strMap http_x_forwarded_for_data;
    http_x_forwarded_for_data.reserve(2048);
    strMap http_sent_data;
    http_sent_data.reserve(16384);
    statusMap http_bad_code_data;

    while (fh.getline(str, sizeof(str)))
    {
        Line a(str);
        if (a.parse_remote_addr(value) < 0)
        {
            std::cerr << str << std::endl;
            continue;
        }
        std::string remote_addr(value);
        if (a.parse_remote_user(value) < 0)
        {
            std::cerr << str << std::endl;
            continue;
        }
        std::string remote_user(value);
        if (a.parse_time_local(value) < 0)
        {
            std::cerr << str << std::endl;
            continue;
        }
        std::string time_local(value);
        if (a.parse_request_line(value) < 0)
        {
            std::cerr << str << std::endl;
            continue;
        }
        std::string request_line(value);

        if (a.parse_status_code(value) < 0)
        {
            std::cerr << str << std::endl;
            continue;
        }
        std::string status_code(value);

        if (a.parse_body_bytes_sent(value) < 0)
        {
            std::cerr << str << std::endl;
            continue;
        }
        int body_bytes_sent = atoi(value);

        if (a.parse_http_referer(value) < 0)
        {
            std::cerr << str << std::endl;
            continue;
        }
        std::string http_referer(value);

        if (a.parse_http_user_agent(value) < 0)
        {
            std::cerr << str << std::endl;
            continue;
        }
        std::string http_user_agent(value);

        if (a.parse_http_x_forwarded_for(value) < 0)
        {
            std::cerr << str << std::endl;
            continue;
        }
        std::string http_x_forwarded_for(value);

        // 这一行 所有都已正确解析，插入table中
        total_lines++;
        total_bytes_sent += body_bytes_sent;

        remote_addr_data[remote_addr] += 1;
        remote_user_data[remote_user] += 1;
        time_local_data[time_local] += 1;
        request_line_data[request_line] += 1;
        status_data[status_code] += 1;
        http_referer_data[http_referer] += 1;
        http_user_agent_data[http_user_agent] += 1;
        http_x_forwarded_for_data[http_x_forwarded_for] += 1;
        http_sent_data[request_line] += body_bytes_sent;
        if (status_code != "200")
        {
            http_bad_code_data[status_code][request_line] += 1;
        }
    }
    byteFormat(total_bytes_sent, value);
    const unsigned int ip_count = remote_addr_data.size();
    printf("\n共计\e[1;34m%u\e[00m次访问\n发送总流量\e[1;32m%s\e[00m\n独立IP数\e[1;31m%u\e[00m\n", total_lines, value, ip_count);
    if (total_lines < 1)
    {
        return 0;
    }
    const int t_width = get_width() - 16;
    const unsigned int limit = 100;
    const auto t_width_str = std::to_string(t_width);

    auto print_stat_long = [&](const std::string &name, strMap &m)
    {
        std::cout << "\n\e[1;34m" << name << "\e[00m" << std::endl;
        const auto data = sort_map(m);
        int n = 0;
        for (unsigned int i = 0; i < m.size(); i++)
        {
            if (i >= limit)
            {
                break;
            }
            const auto &u = data[i].second;
            const auto &num = data[i].first;
            printf(("%-" + t_width_str + ".*s %6d %.2f%%\n").c_str(), t_width, u.c_str(), num, ((double)num / (double)total_lines) * 100);
            n += num;
        }
        snprintf(value, sizeof(value), "%d/%d", n, total_lines);
        printf(("前%d项占比\n%-" + t_width_str + "s %6d %.2f%%\n\n").c_str(), limit, value, m.size(), ((double)n / (double)total_lines) * 100);
        delete[] data;
        m.clear();
    };

    auto print_sent_long = [&](const std::string &name, strMap &m)
    {
        std::cout << "\n\e[1;34m" << name << "\e[00m" << std::endl;
        const auto data = sort_map(m);
        int n = 0;
        const int max_width = t_width - 6;
        const std::string max_width_str = std::to_string(max_width);
        for (unsigned int i = 0; i < m.size(); i++)
        {
            if (i >= limit)
            {
                break;
            }
            const auto &u = data[i].second;
            const auto &num = data[i].first;
            byteFormat(num, value);
            printf(("%-" + max_width_str + ".*s %12s %.2f%%\n").c_str(), max_width, u.c_str(), value, ((double)num / (double)total_bytes_sent) * 100);
            n += num;
        }
        char b1[128] = {0};
        char b2[128] = {0};
        byteFormat(n, b1);
        byteFormat(total_bytes_sent, b2);
        snprintf(value, sizeof(value), "%s/%s", b1, b2);
        printf(("前%d项占比\n%-" + max_width_str + "s %12d %.2f%%\n\n").c_str(), limit, value, m.size(), ((double)n / (double)total_bytes_sent) * 100);
        delete[] data;
        m.clear();
    };

    auto print_code_long = [&](const std::string &name, strMap &m)
    {
        const auto data = sort_map(m);
        int count = 0;
        for (unsigned int i = 0; i < m.size(); i++)
        {
            count += data[i].first;
        }
        snprintf(value, sizeof(value), "%.2f", (double)(count * 100) / (double)total_lines);
        std::cout << "\n\e[1;34m状态码" << name << ",共" << count << "次,占比" << value << "%\e[00m" << std::endl;
        int n = 0;
        for (unsigned int i = 0; i < m.size(); i++)
        {
            if (i >= limit)
            {
                break;
            }
            const auto &u = data[i].second;
            const auto &num = data[i].first;
            printf(("%-" + t_width_str + ".*s %6d %.2f%%\n").c_str(), t_width, u.c_str(), num, ((double)num / (double)count) * 100);
            n += num;
        }
        snprintf(value, sizeof(value), "%d/%d", n, count);
        printf(("前%d项占比\n%-" + t_width_str + "s %6d %.2f%%\n\n").c_str(), limit, value, m.size(), ((double)n / (double)count) * 100);
        delete[] data;
        m.clear();
    };

    print_stat_long("来访IP统计", remote_addr_data);

    print_stat_long("用户统计", remote_user_data);

    print_stat_long("代理IP统计", http_x_forwarded_for_data);

    print_stat_long("HTTP请求统计", request_line_data);

    print_stat_long("User-Agent统计", http_user_agent_data);

    print_stat_long("HTTP REFERER 统计", http_referer_data);

    print_stat_long("请求时间统计", time_local_data);

    print_stat_long("HTTP响应状态统计", status_data);

    print_sent_long("HTTP流量占比统计", http_sent_data);

    // 非200状态码
    const auto http_bad_code_data_sort = sort_strmap(http_bad_code_data);
    for (unsigned int i = 0; i < http_bad_code_data.size(); i++)
    {
        print_code_long(http_bad_code_data_sort[i].first, http_bad_code_data_sort[i].second);
    }
    delete[] http_bad_code_data_sort;
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        return process(std::cin);
    }
    // ifstream是输入文件流（input file stream）的简称, std::ifstream
    // 离开作用域后，fh文件将被析构器自动关闭
    std::ifstream fh(argv[1]); // 打开一个文件
    if (!fh)
    {
        // open file failed
        perror(argv[1]);
        return 1;
    }
    char buf[81920];
    fh.rdbuf()->pubsetbuf(buf, sizeof(buf));
    return process(fh);
}