#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <array>
#include <vector>
#include <unordered_map>
#include <sys/ioctl.h> // ioctl() and TIOCGWINSZ
#include <unistd.h>    // for STDOUT_FILENO

using namespace std;

typedef unordered_map<string, int> strMap;
typedef unordered_map<string, strMap> statusMap;
typedef pair<int, string> intstr;
typedef pair<string, strMap> strstrMap;

typedef int (*char_is_match)(unsigned char x, unsigned char y, unsigned char z);

// 此变量解析每行时需置为0，模拟闭包
int space_count = 0;
// 当前字符是双引号，下个字符是空格，上个字符是http版本,并且只能包含2个空格
int request_line_quote_end(unsigned char x, unsigned char y, unsigned char z)
{
    if (x == 32)
    {
        space_count++;
    }
    if (space_count > 2)
    {
        return 0;
    }
    if (x == 34 && y == 32 && (z == 49 || z == 48))
    {
        return 0;
    }
    return 1;
}

// 仅数字
int digital(unsigned char x, unsigned char y, unsigned char z)
{
    return x >= 48 && x <= 57;
}

// 包含数字和.号
int digital_dot(unsigned char x, unsigned char y, unsigned char z)
{
    return (x >= 48 && x <= 57) || x == 46;
}

// 包含数字和.号或-号
int digital_dot_minus(unsigned char x, unsigned char y, unsigned char z)
{
    return (x >= 48 && x <= 57) || x == 46 || x == 45;
}

// 匹配到],并且下一个是空格
int square_right_space(unsigned char x, unsigned char y, unsigned char z)
{
    if (x == 93 && y == 32)
    {
        return 0;
    }
    return 1;
}

// 非空格
int not_space(unsigned char x, unsigned char y, unsigned char z)
{
    return x != 32;
}

// 包含2个双引号，匹配到第二个双引号结束
int quote_count = 0;
int quote_string_end(unsigned char x, unsigned char y, unsigned char z)
{
    if (x == 34)
    {
        quote_count++;
    }
    if (x == 34 && quote_count == 2)
    {
        return 0;
    }
    return 1;
}

// 当前字符是空格，上个字符是字母,不包含空格
int string_end(unsigned char x, unsigned char y, unsigned char z)
{
    if (x == 32 && ((z >= 65 && z <= 90) || (z >= 97 && z <= 122)))
    {
        return 0;
    }
    return 1;
}

// 当前是空格，上一个是-或者数字
int digital_or_none_end(unsigned char x, unsigned char y, unsigned char z)
{
    if (x == 32 && ((z >= 48 && z <= 57) || z == 45))
    {
        return 0;
    }
    return 1;
}

class Line
{
private:
    int index;
    int len;
    char const *str;

    int
    parse_item_trim_space(char *item_value, char_is_match cond, int strip_square, int result_strip_left_quote)
    {
        int pad = 1;
        int found_start = -1;
        int found_end = -1;
        int gotvalue = -1;
        int i = index;
        while (i < len)
        {
            unsigned char x = str[i];
            i++;
            if ((x == ' ' || (strip_square && x == '[')) && pad)
            {
                index = i;
                continue;
            }
            else
            {
                pad = 0;
            }
            if (gotvalue < 0)
            {
                unsigned char y = i < len ? str[i] : 0;
                unsigned char z = i >= 2 ? str[i - 2] : 0;
                if (cond(x, y, z))
                {
                    found_end = i - 1;
                    if (found_start < 0)
                    {
                        found_start = found_end;
                    }
                    if (i < len)
                    {
                        continue;
                    }
                }
                if (found_start < 0)
                {
                    goto end;
                }
                // 包含cond成立时当前字符x,如果结果字符串以某字符开始，我们配置了result_strip_left_quote开头
                // 例如解析request_line,开头有引号,我们仅在生成结果时过滤
                if (result_strip_left_quote > 0)
                {
                    while (found_start < found_end)
                    {
                        if (str[found_start] == 34)
                        {
                            found_start++;
                        }
                        else
                        {
                            break;
                        }
                    }
                }
                int v_len = found_end - found_start + 1;
                strncpy(item_value, str + found_start, v_len);
                item_value[v_len] = '\0';
                gotvalue = 1;
                if (i >= len)
                {
                    if (found_end == len - 1 || x == ' ')
                    {
                        // 字符串已完全遍历
                        index = len;
                    }
                    else
                    {
                        index = found_end + 1;
                    }
                }
            }
            else
            {
                if (x == ' ' || (strip_square && x == ']'))
                {
                    if (i < len)
                    {
                        continue;
                    }
                    else if (i == len)
                    {
                        i++;
                    }
                }
                index = i - 1;
                break;
            }
        }
    end:
        return found_start;
    }

public:
    Line(char const *str);

    int parse_remote_addr(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_dot, 0, 0);
    }

    int parse_remote_user(char *item_value)
    {
        int i = index;
        while (i < len)
        {
            if (str[i] == '-')
            {
                i++;
            }
            else
            {
                break;
            }
        }
        index = i;
        return parse_item_trim_space(item_value, not_space, 0, 0);
    }

    int parse_time_local(char *item_value)
    {
        return parse_item_trim_space(item_value, square_right_space, 1, 0);
    }

    int parse_request_line(char *item_value)
    {
        space_count = 0;
        return parse_item_trim_space(item_value, request_line_quote_end, 0, 1);
    }

    int parse_status_code(char *item_value)
    {
        return parse_item_trim_space(item_value, digital, 0, 0);
    }

    int parse_body_bytes_sent(char *item_value)
    {
        return parse_item_trim_space(item_value, digital, 0, 0);
    }

    int parse_http_referer(char *item_value)
    {
        quote_count = 0;
        return parse_item_trim_space(item_value, quote_string_end, 0, 1);
    }

    int parse_http_user_agent(char *item_value)
    {
        quote_count = 0;
        return parse_item_trim_space(item_value, quote_string_end, 0, 1);
    }

    int parse_http_x_forwarded_for(char *item_value)
    {
        quote_count = 0;
        return parse_item_trim_space(item_value, quote_string_end, 0, 1);
    }

    int parse_host(char *item_value)
    {
        return parse_item_trim_space(item_value, string_end, 0, 0);
    }

    int parse_request_length(char *item_value)
    {
        return parse_item_trim_space(item_value, digital, 0, 0);
    }

    int parse_bytes_sent(char *item_value)
    {
        return parse_item_trim_space(item_value, digital, 0, 0);
    }

    int parse_upstream_addr(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_or_none_end, 0, 0);
    }

    int parse_upstream_status(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_or_none_end, 0, 0);
    }

    int parse_request_time(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_dot, 0, 0);
    }

    int parse_upstream_response_time(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_dot_minus, 0, 0);
    }

    int parse_upstream_connect_time(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_dot_minus, 0, 0);
    }

    int parse_upstream_header_time(char *item_value)
    {
        return parse_item_trim_space(item_value, digital_dot_minus, 0, 0);
    }
};

Line::Line(char const *line)
{
    str = line;
    index = 0;
    len = strlen(line);
}

static inline void byteFormat(unsigned int s, char *out)
{
    char const *unit = "KMGTPEZY";
    if (s < 1024)
    {
        sprintf(out, "%u B", s);
        return;
    }
    unit--;
    float n = (float)s;
    while (n >= 1024)
    {
        n /= 1024;
        unit++;
    }
    sprintf(out, "%.2f %cB", n, *unit);
}

intstr *sort_map(strMap &m)
{
    int i = 0;
    auto arr = new intstr[m.size()];
    for (const auto &it : m)
    {
        arr[i] = make_pair(it.second, it.first);
        i++;
    }
    sort(arr, arr + m.size(), greater<>());
    return arr;
}

static inline int cmp(strstrMap a, strstrMap b)
{
    return a.first < b.first;
}

// pair 默认对first升序，当first相同时对second升序；
// 我们的second无法比较，需要自定义cmp函数
strstrMap *sort_strmap(statusMap &m)
{
    int i = 0;
    auto arr = new strstrMap[m.size()];
    for (const auto &it : m)
    {
        arr[i] = make_pair(it.first, it.second);
        i++;
    }
    sort(arr, arr + m.size(), cmp);
    return arr;
}

int get_width()
{
    struct winsize size;
    char fds[3] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
    for (int fd = 0; fd < sizeof(fds) / sizeof(fds[0]); fd++)
    {
        if (ioctl(fd, TIOCGWINSZ, &size) != -1)
        {
            break;
        }
    }
    return size.ws_col;
}

int process(istream &fh)
{
    string str;
    char value[8192] = {0}; // 后面多处使用此内存池复用
    unsigned long total_bytes_sent = 0;
    unsigned int total_lines = 0;

    strMap remote_addr_data;
    strMap remote_user_data;
    strMap time_local_data;
    strMap request_line_data;
    strMap status_data;
    strMap http_referer_data;
    strMap http_user_agent_data;
    strMap http_x_forwarded_for_data;
    strMap http_sent_data;
    statusMap http_bad_code_data;

    while (getline(fh, str))
    {
        auto a = Line(str.c_str());
        if (a.parse_remote_addr(value) < 0)
        {
            cerr << str << endl;
            continue;
        }
        string remote_addr = value;
        if (a.parse_remote_user(value) < 0)
        {
            cerr << str << endl;
            continue;
        }
        string remote_user = value;
        if (a.parse_time_local(value) < 0)
        {
            cerr << str << endl;
            continue;
        }
        string time_local = value;
        if (a.parse_request_line(value) < 0)
        {
            cerr << str << endl;
            continue;
        }
        string request_line = value;

        if (a.parse_status_code(value) < 0)
        {
            cerr << str << endl;
            continue;
        }
        string status_code = value;

        if (a.parse_body_bytes_sent(value) < 0)
        {
            cerr << str << endl;
            continue;
        }
        int body_bytes_sent = atoi(value);

        if (a.parse_http_referer(value) < 0)
        {
            cerr << str << endl;
            continue;
        }
        string http_referer = value;

        if (a.parse_http_user_agent(value) < 0)
        {
            cerr << str << endl;
            continue;
        }
        string http_user_agent = value;

        if (a.parse_http_x_forwarded_for(value) < 0)
        {
            cerr << str << endl;
            continue;
        }
        string http_x_forwarded_for = value;

        // 这一行 所有都已正确解析，插入table中
        total_lines++;
        total_bytes_sent += body_bytes_sent;

        if (remote_addr_data.find(remote_addr) != remote_addr_data.end())
        {
            ++remote_addr_data[remote_addr];
        }
        else
        {
            remote_addr_data[remote_addr] = 1;
        }

        if (remote_user_data.find(remote_user) != remote_user_data.end())
        {
            ++remote_user_data[remote_user];
        }
        else
        {
            remote_user_data[remote_user] = 1;
        }

        if (time_local_data.find(time_local) != time_local_data.end())
        {
            ++time_local_data[time_local];
        }
        else
        {
            time_local_data[time_local] = 1;
        }

        if (request_line_data.find(request_line) != request_line_data.end())
        {
            ++request_line_data[request_line];
        }
        else
        {
            request_line_data[request_line] = 1;
        }

        if (status_data.find(status_code) != status_data.end())
        {
            ++status_data[status_code];
        }
        else
        {
            status_data[status_code] = 1;
        }

        if (http_referer_data.find(http_referer) != http_referer_data.end())
        {
            ++http_referer_data[http_referer];
        }
        else
        {
            http_referer_data[http_referer] = 1;
        }

        if (http_user_agent_data.find(http_user_agent) != http_user_agent_data.end())
        {
            ++http_user_agent_data[http_user_agent];
        }
        else
        {
            http_user_agent_data[http_user_agent] = 1;
        }

        if (http_x_forwarded_for_data.find(http_x_forwarded_for) != http_x_forwarded_for_data.end())
        {
            ++http_x_forwarded_for_data[http_x_forwarded_for];
        }
        else
        {
            http_x_forwarded_for_data[http_x_forwarded_for] = 1;
        }

        if (http_sent_data.find(request_line) != http_sent_data.end())
        {
            http_sent_data[request_line] += body_bytes_sent;
        }
        else
        {
            http_sent_data[request_line] = body_bytes_sent;
        }

        if (status_code != "200")
        {
            if (http_bad_code_data.find(status_code) != http_bad_code_data.end())
            {
                auto &x = http_bad_code_data[status_code];
                if (x.find(request_line) != x.end())
                {
                    x[request_line] += 1;
                }
                else
                {
                    x[request_line] = 1;
                }
            }
            else
            {
                strMap badreq;
                badreq[request_line] = 1;
                http_bad_code_data[status_code] = badreq;
            }
        }
    }
    byteFormat(total_bytes_sent, value);
    unsigned int ip_count = remote_addr_data.size();
    printf("\n共计\e[1;34m%u\e[00m次访问\n发送总流量\e[1;32m%s\e[00m\n独立IP数\e[1;31m%u\e[00m\n", total_lines, value, ip_count);
    int t_width = get_width() - 16;
    int limit = 100;
    auto t_width_str = to_string(t_width);

    auto print_stat_long = [&](const string name, strMap &m)
    {
        cout << "\n\e[1;34m" << name << "\e[00m" << endl;
        auto data = sort_map(m);
        int n = 0;
        for (int i = 0; i < m.size(); i++)
        {
            auto u = data[i].second;
            auto num = data[i].first;
            printf(("%-" + t_width_str + ".*s %6d %.2f%%\n").c_str(), t_width, u.c_str(), num, ((double)num / (double)total_lines) * 100);
            n += num;
            if (i >= limit)
            {
                break;
            }
        }
        snprintf(value, sizeof(value), "%d/%d", n, total_lines);
        printf(("前%d项占比\n%-" + t_width_str + "s %6d %.2f%%\n\n").c_str(), limit, value, m.size(), ((double)n / (double)total_lines) * 100);
        delete[] data;
        m.clear();
    };

    auto print_sent_long = [&](const string name, strMap &m)
    {
        cout << "\n\e[1;34m" << name << "\e[00m" << endl;
        auto data = sort_map(m);
        int i = 0;
        int n = 0;
        int max_width = t_width - 6;
        string max_width_str = to_string(max_width);
        for (int i = 0; i < m.size(); i++)
        {
            auto u = data[i].second;
            auto num = data[i].first;
            byteFormat(num, value);
            printf(("%-" + max_width_str + ".*s %12s %.2f%%\n").c_str(), max_width, u.c_str(), value, ((double)num / (double)total_bytes_sent) * 100);
            n += num;
            if (i >= limit)
            {
                break;
            }
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

    auto print_code_long = [&](const string name, strMap &m)
    {
        auto data = sort_map(m);
        int count = 0;
        for (int i = 0; i < m.size(); i++)
        {
            count += data[i].first;
        }
        cout << "\n\e[1;34m状态码" << name << ",共" << count << "次\e[00m" << endl;
        int n = 0;
        for (int i = 0; i < m.size(); i++)
        {
            auto u = data[i].second;
            auto num = data[i].first;
            printf(("%-" + t_width_str + ".*s %6d %.2f%%\n").c_str(), t_width, u.c_str(), num, ((double)num / (double)total_lines) * 100);
            n += num;
            if (++i >= limit)
            {
                break;
            }
        }
        snprintf(value, sizeof(value), "%d/%d", n, total_lines);
        printf(("前%d项占比\n%-" + t_width_str + "s %6d %.2f%%\n\n").c_str(), limit, value, m.size(), ((double)n / (double)total_lines) * 100);
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
    auto http_bad_code_data_sort = sort_strmap(http_bad_code_data);
    for (int i = 0; i < http_bad_code_data.size(); i++)
    {
        print_code_long(http_bad_code_data_sort[i].first, http_bad_code_data_sort[i].second);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    istream *in;
    ifstream ifn;

    if (argc < 2)
    {
        return process(cin);
    }
    // ifstream是输入文件流（input file stream）的简称, std::ifstream
    // 离开作用域后，fh文件将被析构器自动关闭
    ifstream fh(argv[1]); // 打开一个文件
    if (!fh)
    {
        // open file failed
        perror(argv[1]);
        return 1;
    }
    return process(fh);
}