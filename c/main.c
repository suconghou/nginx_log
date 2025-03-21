#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h> // ioctl() and TIOCGWINSZ
#include <unistd.h>    // for STDOUT_FILENO

#include "hash.c"

typedef int (*char_is_match)(unsigned char x, unsigned char y);

// 仅数字
int digital(unsigned char x, unsigned char y)
{
    return x >= 48 && x <= 57;
}

// 包含数字和.号
int digital_dot(unsigned char x, unsigned char y)
{
    return (x >= 48 && x <= 57) || x == 46;
}

// 包含数字字母[a-f]和.号或:号（IPv4或IPv6）
int digital_dot_colon(unsigned char x, unsigned char y)
{
    return (x >= 48 && x <= 58) || x == 46 || (x >= 97 && x <= 102);
}

// 包含数字和.号或-号
int digital_dot_minus(unsigned char x, unsigned char y)
{
    return (x >= 48 && x <= 57) || x == 46 || x == 45;
}

// 非空格
int not_space(unsigned char x, unsigned char y)
{
    return x != 32;
}

// 当前是空格，上一个是-或者数字
int digital_or_none_end(unsigned char x, unsigned char y)
{
    return !(x == 32 && ((y >= 48 && y <= 57) || y == 45));
}

int parse_item_trim_space(const char *s, const char **pos_ptr, const char *end, char *item_value, char_is_match cond)
{
    const char *pos = *pos_ptr;
    while (pos < end && *pos == ' ')
    {
        ++pos;
    }
    *pos_ptr = pos;
    const char *found_start = NULL;
    const char *found_end = NULL;
    unsigned char y = (pos > s) ? *(pos - 1) : 0;
    while (pos < end)
    {
        unsigned char x = *pos++;
        if (cond(x, y))
        {
            y = x;
            found_end = pos - 1;
            if (!found_start)
            {
                found_start = found_end;
            }
            if (pos < end)
            {
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
        while (pos < end && *pos == ' ')
        {
            ++pos;
        }
        *pos_ptr = pos;
        return found_start - s;
    }
    return found_start ? (found_start - s) : -1;
}

int parse_item_wrap_string(const char *s, const char **pos_ptr, const char *end, char *item_value, const char left, const char right)
{
    const char *pos = *pos_ptr;
    while (pos < end && *pos == ' ')
    {
        ++pos;
    }
    if (pos >= end || *pos != left)
    {
        return -1;
    }
    ++pos;
    const char *p = memchr(pos, right, end - pos);
    if (!p)
    {
        return -1;
    }
    const int v_len = p - pos;
    memcpy(item_value, pos, v_len);
    item_value[v_len] = '\0';
    *pos_ptr = p + 1;
    return 1;
}

int parse_remote_addr(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, digital_dot_colon);
}

int parse_remote_user(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    const char *pos = *pos_ptr;

    while (pos < end && *pos == '-')
    {
        ++pos;
    }

    *pos_ptr = pos;
    return parse_item_trim_space(s, pos_ptr, end, item_value, not_space);
}

int parse_time_local(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_wrap_string(s, pos_ptr, end, item_value, '[', ']');
}

int parse_request_line(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_wrap_string(s, pos_ptr, end, item_value, '"', '"');
}

int parse_status_code(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, digital);
}

int parse_body_bytes_sent(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, digital);
}

int parse_http_referer(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_wrap_string(s, pos_ptr, end, item_value, '"', '"');
}

int parse_http_user_agent(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_wrap_string(s, pos_ptr, end, item_value, '"', '"');
}

int parse_http_x_forwarded_for(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_wrap_string(s, pos_ptr, end, item_value, '"', '"');
}

int parse_host(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, not_space);
}

int parse_request_length(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, digital);
}

int parse_bytes_sent(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, digital);
}

int parse_upstream_addr(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, not_space);
}

int parse_upstream_status(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, digital_or_none_end);
}

int parse_request_time(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, digital_dot);
}

int parse_upstream_response_time(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, digital_dot_minus);
}

int parse_upstream_connect_time(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, digital_dot_minus);
}

int parse_upstream_header_time(const char *s, const char **pos_ptr, const char *end, char *item_value)
{
    return parse_item_trim_space(s, pos_ptr, end, item_value, digital_dot_minus);
}

static inline void byteFormat(const unsigned long s, char *out)
{
    char *unit = "KMGTPEZY";
    if (s < 1024)
    {
        sprintf(out, "%lu B", s);
        return;
    }
    unit--;
    double n = (double)s;
    while (n >= 1024)
    {
        n /= 1024;
        unit++;
    }
    sprintf(out, "%.2f %cB", n, *unit);
}

static unsigned int get_width()
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

int print_stat_long(const char *name, table *map, const unsigned int total_lines, const unsigned int t_width, const char *t_width_str)
{
    printf("\n\e[1;34m%s\e[00m\n", name);
    const unsigned int len = map->counter;
    tableItem **data = sort(map);
    unsigned long n = 0;
    const int limit = 100;
    char buf[128] = {0};
    char value[1024] = {0};
    for (int i = 0; i < len; i++)
    {
        if (i >= limit)
        {
            free(data[i]);
            continue;
        }
        const char *u = data[i]->key;
        const unsigned int num = data[i]->value;
        strcpy(value, "%-");
        strcat(value, t_width_str);
        strcat(value, ".*s %6d %.2f%%\n");
        printf(value, t_width, u, num, ((double)num / (double)total_lines) * 100);
        n += num;
        free(data[i]);
    }
    snprintf(buf, sizeof(buf), "%lu/%d", n, total_lines);
    strcpy(value, "前%d项占比\n%-");
    strcat(value, t_width_str);
    strcat(value, "s %6d %.2f%%\n\n");
    printf(value, limit, buf, len, ((double)n / (double)total_lines) * 100);
    free(data);
    return 0;
}

int print_sent_long(const char *name, table *map, const unsigned int total_lines, const unsigned long total_bytes_sent, const unsigned int t_width)
{
    printf("\n\e[1;34m%s\e[00m\n", name);
    const unsigned int len = map->counter;
    tableItem **data = sort(map);
    const int max_width = t_width - 6;
    const int limit = 100;
    unsigned long n = 0;
    char buf[128] = {0};
    char value[1024] = {0};
    char max_width_str[12];
    sprintf(max_width_str, "%d", max_width);

    for (int i = 0; i < len; i++)
    {
        if (i >= limit)
        {
            free(data[i]);
            continue;
        }
        const char *u = data[i]->key;
        const unsigned int num = data[i]->value;
        strcpy(value, "%-");
        strcat(value, max_width_str);
        strcat(value, ".*s %12s %.2f%%\n");
        byteFormat(num, buf);
        printf(value, max_width, u, buf, ((double)num / (double)total_bytes_sent) * 100);
        n += num;
        free(data[i]);
    }
    char b1[128] = {0};
    char b2[128] = {0};
    byteFormat(n, b1);
    byteFormat(total_bytes_sent, b2);
    snprintf(buf, sizeof(buf), "%s/%s", b1, b2);
    strcpy(value, "前%d项占比\n%-");
    strcat(value, max_width_str);
    strcat(value, "s %12d %.2f%%\n\n");
    printf(value, limit, buf, len, ((double)n / (double)total_bytes_sent) * 100);
    free(data);
    return 0;
}

int print_code_long(int status_code, table *map, const unsigned int total_lines, const unsigned int t_width, const char *t_width_str)
{
    unsigned int total = 0;
    const unsigned int len = map->counter;
    tableItem **data = sort(map);
    for (int i = 0; i < len; i++)
    {
        total += data[i]->value;
    }
    printf("\n\e[1;34m状态码%d,共%d次,占比%.2f%%\e[00m\n", status_code, total, (double)(100 * total) / (double)total_lines);
    unsigned long n = 0;
    const int limit = 100;
    char buf[128] = {0};
    char value[1024] = {0};
    for (int i = 0; i < len; i++)
    {
        if (i >= limit)
        {
            free(data[i]);
            continue;
        }
        const char *u = data[i]->key;
        const unsigned int num = data[i]->value;
        strcpy(value, "%-");
        strcat(value, t_width_str);
        strcat(value, ".*s %6d %.2f%%\n");
        printf(value, t_width, u, num, ((double)num / (double)total) * 100);
        n += num;
        free(data[i]);
    }
    snprintf(buf, sizeof(buf), "%lu/%d", n, total);
    strcpy(value, "前%d项占比\n%-");
    strcat(value, t_width_str);
    strcat(value, "s %6d %.2f%%\n\n");
    printf(value, limit, buf, len, ((double)n / (double)total) * 100);
    free(data);
    return 0;
}

int main(int argc, char *argv[])
{
    FILE *input;

    // FILE *input = fopen("/tmp/1", "r");
    if (argc < 2)
    {
        input = stdin;
    }
    else
    {
        input = fopen(argv[1], "r");
        if (input == NULL)
        {
            perror(argv[1]);
            return 1;
        }
    }

    char s[8192];

    // 必须是2的n次方，只有这样才能使得，取余简化
    // k % 2^n = k & (2^n - 1)
    table *remote_addr_data = newTable(8192);
    table *remote_user_data = newTable(64);
    table *time_local_data = newTable(16384);
    table *request_line_data = newTable(16384);
    table *status_data = newTable(64);
    table *http_referer_data = newTable(8192);
    table *http_user_agent_data = newTable(8192);
    table *http_x_forwarded_for_data = newTable(2048);
    table *http_sent_data = newTable(16384);
    table *http_bad_code_data[999] = {NULL};

    unsigned long total_bytes_sent = 0;
    unsigned int total_lines = 0;
    char remote_addr[1024] = {0};
    char remote_user[1024] = {0};
    char time_local[1024] = {0};
    char request_line[8192] = {0};
    char status_code[32] = {0};
    char http_referer[4096] = {0};
    char http_user_agent[4096] = {0};
    char http_x_forwarded_for[1024] = {0};

    while (fgets(s, sizeof s, input) != NULL)
    {

        const char *pos = s;
        const char *end = s + strlen(s);

        if (parse_remote_addr(s, &pos, end, remote_addr) < 0)
        {
            goto error_line;
        }
        if (parse_remote_user(s, &pos, end, remote_user) < 0)
        {
            goto error_line;
        }
        if (parse_time_local(s, &pos, end, time_local) < 0)
        {
            goto error_line;
        }
        if (parse_request_line(s, &pos, end, request_line) < 0)
        {
            goto error_line;
        }
        if (parse_status_code(s, &pos, end, status_code) < 0)
        {
            goto error_line;
        }
        if (strlen(status_code) != 3)
        {
            // 状态码必须是三位数字
            goto error_line;
        }
        char buf[64] = {0};
        if (parse_body_bytes_sent(s, &pos, end, buf) < 0)
        {
            goto error_line;
        }
        int body_bytes_sent = atoi(buf);
        if (parse_http_referer(s, &pos, end, http_referer) < 0)
        {
            goto error_line;
        }
        if (parse_http_user_agent(s, &pos, end, http_user_agent) < 0)
        {
            goto error_line;
        }
        if (parse_http_x_forwarded_for(s, &pos, end, http_x_forwarded_for) < 0)
        {
            goto error_line;
        }
        // 这一行 所有都已正确解析，插入table中
        total_lines++;
        total_bytes_sent += body_bytes_sent;

        incr(remote_addr_data, remote_addr, 1);
        incr(remote_user_data, remote_user, 1);
        incr(time_local_data, time_local, 1);
        incr(request_line_data, request_line, 1);
        incr(status_data, status_code, 1);
        incr(http_referer_data, http_referer, 1);
        incr(http_user_agent_data, http_user_agent, 1);
        incr(http_x_forwarded_for_data, http_x_forwarded_for, 1);
        incr(http_sent_data, request_line, body_bytes_sent);
        if (strcmp(status_code, "200") != 0)
        {
            const unsigned int status_code_int = atoi(status_code);
            if (http_bad_code_data[status_code_int] == NULL)
            {
                http_bad_code_data[status_code_int] = newTable(1024);
            }
            incr(http_bad_code_data[status_code_int], request_line, 1);
        }
        continue;

    error_line:

        fprintf(stderr, "%s", s);
    }

    // 分析完毕后，排序然后，打印统计数据

    char str_sent[64];
    byteFormat(total_bytes_sent, str_sent);
    unsigned int ip_count = remote_addr_data->counter;
    printf("\n共计\e[1;34m%u\e[00m次访问\n发送总流量\e[1;32m%s\e[00m\n独立IP数\e[1;31m%u\e[00m\n", total_lines, str_sent, ip_count);
    if (total_lines < 1)
    {
        return 0;
    }
    unsigned int t_width = get_width() - 16;
    char t_width_str[16];
    sprintf(t_width_str, "%d", t_width);

    print_stat_long("来访IP统计", remote_addr_data, total_lines, t_width, t_width_str);

    print_stat_long("用户统计", remote_user_data, total_lines, t_width, t_width_str);

    print_stat_long("代理IP统计", http_x_forwarded_for_data, total_lines, t_width, t_width_str);

    print_stat_long("HTTP请求统计", request_line_data, total_lines, t_width, t_width_str);

    print_stat_long("User-Agent统计", http_user_agent_data, total_lines, t_width, t_width_str);

    print_stat_long("HTTP REFERER 统计", http_referer_data, total_lines, t_width, t_width_str);

    print_stat_long("请求时间统计", time_local_data, total_lines, t_width, t_width_str);

    print_stat_long("HTTP响应状态统计", status_data, total_lines, t_width, t_width_str);

    print_sent_long("HTTP流量占比统计", http_sent_data, total_lines, total_bytes_sent, t_width);
    // 非200状态码
    for (int i = 0; i < sizeof(http_bad_code_data) / sizeof(*http_bad_code_data); i++)
    {
        if (http_bad_code_data[i] != NULL)
        {
            print_code_long(i, http_bad_code_data[i], total_lines, t_width, t_width_str);
        }
    }
    return 0;
}
