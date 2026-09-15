#include <string>
#include <cstring>
#include <string_view>
#include <optional>
#include <charconv>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <iostream>
#include <array>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include <sys/ioctl.h> // ioctl() and TIOCGWINSZ
#include <unistd.h>    // for STDOUT_FILENO

// 透明哈希：允许用 string_view 直接查找，避免每行构造 std::string 临时对象
struct str_hash
{
    using is_transparent = void;
    std::size_t operator()(std::string_view sv) const noexcept
    {
        return std::hash<std::string_view>{}(sv);
    }
};
using strMap = std::unordered_map<std::string, int, str_hash, std::equal_to<>>;
using statusMap = std::unordered_map<int, strMap>;

typedef std::pair<int, std::string_view> P;

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
    std::string_view data;  // 存储整个字符串视图
    size_t current_pos = 0; // 当前处理位置

    template <auto cond>
    std::optional<std::string_view> parse_item_trim_space()
    {
        while (current_pos < data.size() && data[current_pos] == ' ')
        {
            ++current_pos;
        }
        int found_start = -1;
        int found_end = -1;
        unsigned char y = (current_pos > 0) ? data[current_pos - 1] : 0;
        while (current_pos < data.size())
        {
            unsigned char x = data[current_pos++];
            if (cond(x, y)) [[likely]]
            {
                found_end = current_pos - 1;
                if (found_start < 0)
                {
                    found_start = found_end;
                }
                if (current_pos < data.size()) [[likely]]
                {
                    y = x;
                    continue;
                }
            }
            if (found_start < 0) [[unlikely]]
            {
                return std::nullopt;
            }
            while (current_pos < data.size() && data[current_pos] == ' ')
            {
                ++current_pos;
            }
            return data.substr(found_start, found_end - found_start + 1);
        }
        if (found_start >= 0)
        {
            return data.substr(found_start, found_end - found_start + 1);
        }
        return std::nullopt;
    }

    std::optional<std::string_view> parse_item_wrap_string(char left = '"', char right = '"')
    {
        while (current_pos < data.size() && data[current_pos] == ' ')
        {
            ++current_pos;
        }
        if (current_pos >= data.size() || data[current_pos] != left) [[unlikely]]
        {
            return std::nullopt;
        }
        ++current_pos;
        int start_pos = current_pos;
        size_t end_pos = data.find(right, current_pos);
        if (end_pos == std::string_view::npos) [[unlikely]]
        {
            return std::nullopt;
        }
        current_pos = end_pos + 1;
        return data.substr(start_pos, end_pos - start_pos);
    }

public:
    explicit Line(std::string_view sv) : data(sv), current_pos(0) {}

    std::optional<std::string_view> parse_remote_addr()
    {
        return parse_item_trim_space<digital_dot_colon>();
    }

    std::optional<std::string_view> parse_remote_user()
    {
        while (current_pos < data.size() && data[current_pos] == '-')
        {
            ++current_pos;
        }
        return parse_item_trim_space<not_space>();
    }

    std::optional<std::string_view> parse_time_local()
    {
        return parse_item_wrap_string('[', ']');
    }

    std::optional<std::string_view> parse_request_line()
    {
        return parse_item_wrap_string();
    }

    std::optional<std::string_view> parse_status_code()
    {
        return parse_item_trim_space<digital>();
    }

    std::optional<std::string_view> parse_body_bytes_sent()
    {
        return parse_item_trim_space<digital>();
    }

    std::optional<std::string_view> parse_http_referer()
    {
        return parse_item_wrap_string();
    }

    std::optional<std::string_view> parse_http_user_agent()
    {
        return parse_item_wrap_string();
    }

    std::optional<std::string_view> parse_http_x_forwarded_for()
    {
        return parse_item_wrap_string();
    }

    std::optional<std::string_view> parse_host()
    {
        return parse_item_trim_space<not_space>();
    }

    std::optional<std::string_view> parse_request_length()
    {
        return parse_item_trim_space<digital>();
    }

    std::optional<std::string_view> parse_bytes_sent()
    {
        return parse_item_trim_space<digital>();
    }

    std::optional<std::string_view> parse_upstream_addr()
    {
        return parse_item_trim_space<not_space>();
    }

    std::optional<std::string_view> parse_upstream_status()
    {
        return parse_item_trim_space<digital_or_none_end>();
    }

    std::optional<std::string_view> parse_request_time()
    {
        return parse_item_trim_space<digital_dot>();
    }

    std::optional<std::string_view> parse_upstream_response_time()
    {
        return parse_item_trim_space<digital_dot_minus>();
    }

    std::optional<std::string_view> parse_upstream_connect_time()
    {
        return parse_item_trim_space<digital_dot_minus>();
    }

    std::optional<std::string_view> parse_upstream_header_time()
    {
        return parse_item_trim_space<digital_dot_minus>();
    }
};

static inline int sv_to_int(std::string_view sv)
{
    int result = 0;
    std::from_chars(sv.data(), sv.data() + sv.size(), result);
    return result;
}

static inline void bump(strMap &m, std::string_view key, int delta = 1)
{
    auto it = m.find(key);
    if (it == m.end())
    {
        it = m.emplace(std::string(key), 0).first;
    }
    it->second += delta;
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

std::vector<P> top_k(const strMap &m, size_t K) noexcept
{
    if (K == 0)
    {
        return {};
    }
    auto compare = [](const P &a, const P &b)
    {
        return a.first > b.first;
    };
    std::priority_queue<P, std::vector<P>, decltype(compare)> min_heap(compare);
    for (const auto &kv : m)
    {
        if (min_heap.size() < K)
        {
            min_heap.push({kv.second, kv.first});
        }
        else if (kv.second > min_heap.top().first)
        {
            min_heap.pop();
            min_heap.push({kv.second, kv.first});
        }
    }
    const size_t result_size = min_heap.size();
    std::vector<P> result(result_size);
    size_t index = result_size;
    while (!min_heap.empty())
    {
        result[--index] = min_heap.top();
        min_heap.pop();
    }
    return result;
}

int get_width()
{
    struct winsize size = {0, 0, 0, 0};
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

int process(FILE *fh)
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

    while (fgets(str, sizeof(str), fh))
    {
        Line a{std::string_view(str)};
        auto remote_addr = a.parse_remote_addr();
        if (!remote_addr)
        {
            std::cerr << str << std::endl;
            continue;
        }
        auto remote_user = a.parse_remote_user();
        if (!remote_user)
        {
            std::cerr << str << std::endl;
            continue;
        }
        auto time_local = a.parse_time_local();
        if (!time_local)
        {
            std::cerr << str << std::endl;
            continue;
        }
        auto request_line = a.parse_request_line();
        if (!request_line)
        {
            std::cerr << str << std::endl;
            continue;
        }
        auto status_code = a.parse_status_code();
        if (!status_code)
        {
            std::cerr << str << std::endl;
            continue;
        }
        auto body_bytes_sent_sv = a.parse_body_bytes_sent();
        if (!body_bytes_sent_sv)
        {
            std::cerr << str << std::endl;
            continue;
        }
        int body_bytes_sent = sv_to_int(*body_bytes_sent_sv);
        auto http_referer = a.parse_http_referer();
        if (!http_referer)
        {
            std::cerr << str << std::endl;
            continue;
        }
        auto http_user_agent = a.parse_http_user_agent();
        if (!http_user_agent)
        {
            std::cerr << str << std::endl;
            continue;
        }
        auto http_x_forwarded_for = a.parse_http_x_forwarded_for();
        if (!http_x_forwarded_for)
        {
            std::cerr << str << std::endl;
            continue;
        }

        // 这一行 所有都已正确解析
        total_lines++;
        total_bytes_sent += body_bytes_sent;

        bump(remote_addr_data, *remote_addr);
        bump(remote_user_data, *remote_user);
        bump(time_local_data, *time_local);
        bump(request_line_data, *request_line);
        bump(status_data, *status_code);
        bump(http_referer_data, *http_referer);
        bump(http_user_agent_data, *http_user_agent);
        bump(http_x_forwarded_for_data, *http_x_forwarded_for);
        bump(http_sent_data, *request_line, body_bytes_sent);
        if (*status_code != "200")
        {
            bump(http_bad_code_data[sv_to_int(*status_code)], *request_line);
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
        const auto data = top_k(m, limit);
        int n = 0;
        for (const auto &[num, u] : data)
        {
            printf(("%-" + t_width_str + ".*s %6d %.2f%%\n").c_str(), t_width, u.data(), num, ((double)num / (double)total_lines) * 100);
            n += num;
        }
        snprintf(value, sizeof(value), "%d/%d", n, total_lines);
        printf(("前%d项占比\n%-" + t_width_str + "s %6d %.2f%%\n\n").c_str(), limit, value, m.size(), ((double)n / (double)total_lines) * 100);
        m.clear();
    };

    auto print_sent_long = [&](const std::string &name, strMap &m)
    {
        std::cout << "\n\e[1;34m" << name << "\e[00m" << std::endl;
        const auto data = top_k(m, limit);
        int n = 0;
        const int max_width = t_width - 6;
        const std::string max_width_str = std::to_string(max_width);
        for (const auto &[num, u] : data)
        {
            byteFormat(num, value);
            printf(("%-" + max_width_str + ".*s %12s %.2f%%\n").c_str(), max_width, u.data(), value, ((double)num / (double)total_bytes_sent) * 100);
            n += num;
        }
        char b1[128] = {0};
        char b2[128] = {0};
        byteFormat(n, b1);
        byteFormat(total_bytes_sent, b2);
        snprintf(value, sizeof(value), "%s/%s", b1, b2);
        printf(("前%d项占比\n%-" + max_width_str + "s %12d %.2f%%\n\n").c_str(), limit, value, m.size(), ((double)n / (double)total_bytes_sent) * 100);
        m.clear();
    };

    auto print_code_long = [&](int code, strMap &m)
    {
        int count = 0;
        for (const auto &pair : m)
        {
            count += pair.second;
        }
        const auto data = top_k(m, limit);
        snprintf(value, sizeof(value), "%.2f", (double)(count * 100) / (double)total_lines);
        std::cout << "\n\e[1;34m状态码" << code << ",共" << count << "次,占比" << value << "%\e[00m" << std::endl;
        int n = 0;
        for (const auto &[num, u] : data)
        {
            printf(("%-" + t_width_str + ".*s %6d %.2f%%\n").c_str(), t_width, u.data(), num, ((double)num / (double)count) * 100);
            n += num;
        }
        snprintf(value, sizeof(value), "%d/%d", n, count);
        printf(("前%d项占比\n%-" + t_width_str + "s %6d %.2f%%\n\n").c_str(), limit, value, m.size(), ((double)n / (double)count) * 100);
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

    // 非200状态码，按状态码数值升序
    std::vector<std::pair<int, strMap *>> bad_vec;
    for (auto &[code, m] : http_bad_code_data)
    {
        bad_vec.emplace_back(code, &m);
    }
    std::sort(bad_vec.begin(), bad_vec.end(), [](const auto &a, const auto &b)
              { return a.first < b.first; });
    for (auto &[code, m] : bad_vec)
    {
        print_code_long(code, *m);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        return process(stdin);
    }
    FILE *fh = fopen(argv[1], "r");
    if (!fh)
    {
        perror(argv[1]);
        return 1;
    }
    return process(fh);
}
