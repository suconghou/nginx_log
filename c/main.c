#include <stdio.h>
#include <string.h>

#include "hash.c"

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

// 双引号后面是空格
int quote_string_end(unsigned char x, unsigned char y, unsigned char z)
{
    if (x == 34 && y == 32)
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

// offset 字符串坐标
int parse_item_trim_space(const char *s, int *offset, int len, char *item_value, char_is_match cond, int strip_square, int result_strip_left_quote)
{
    int pad = 1;
    int found_start = -1;
    int found_end = -1;
    int gotvalue = -1;
    int i = *offset;
    while (i < len)
    {
        unsigned char x = s[i];
        i++;
        if ((x == ' ' || (strip_square && x == '[')) && pad)
        {
            *offset = i;
            continue;
        }
        else
        {
            pad = 0;
        }
        if (gotvalue < 0)
        {
            unsigned char y = i < len ? s[i] : 0;
            unsigned char z = i >= 2 ? s[i - 2] : 0;
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
                    if (s[found_start] == 34)
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
            strncpy(item_value, s + found_start, v_len);
            item_value[v_len] = '\0';
            gotvalue = 1;
            if (i >= len)
            {
                if (found_end == len - 1 || x == ' ')
                {
                    // 字符串已完全遍历
                    *offset = len;
                }
                else
                {
                    *offset = found_end + 1;
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
            *offset = i - 1;
            break;
        }
    }
end:
    return found_start;
}

int parse_remote_addr(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, digital_dot, 0, 0);
}

int parse_remote_user(const char *s, int *offset, int len, char *item_value)
{
    int i = *offset;
    while (i < len)
    {
        if (s[i] == '-')
        {
            i++;
        }
        else
        {
            break;
        }
    }
    *offset = i;
    return parse_item_trim_space(s, offset, len, item_value, not_space, 0, 0);
}

int parse_time_local(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, square_right_space, 1, 0);
}

int parse_request_line(const char *s, int *offset, int len, char *item_value)
{
    space_count = 0;
    return parse_item_trim_space(s, offset, len, item_value, request_line_quote_end, 0, 1);
}

int parse_status_code(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, digital, 0, 0);
}

int parse_body_bytes_sent(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, digital, 0, 0);
}

int parse_http_referer(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, quote_string_end, 0, 1);
}

int parse_http_user_agent(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, quote_string_end, 0, 1);
}

int parse_http_x_forwarded_for(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, quote_string_end, 0, 1);
}

int parse_host(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, string_end, 0, 0);
}

int parse_request_length(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, digital, 0, 0);
}

int parse_bytes_sent(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, digital, 0, 0);
}

int parse_upstream_addr(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, digital_or_none_end, 0, 0);
}

int parse_upstream_status(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, digital_or_none_end, 0, 0);
}

int parse_request_time(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, digital_dot, 0, 0);
}

int parse_upstream_response_time(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, digital_dot_minus, 0, 0);
}

int parse_upstream_connect_time(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, digital_dot_minus, 0, 0);
}

int parse_upstream_header_time(const char *s, int *offset, int len, char *item_value)
{
    return parse_item_trim_space(s, offset, len, item_value, digital_dot_minus, 0, 0);
}

void byteFormat(unsigned int s, char *out)
{
    char *unit = "KMGTPEZY";
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

int main()
{

    FILE *fp = fopen("/tmp/1", "r");
    if (fp == NULL)
    {
        return -1;
    }
    char s[8192];

    // 必须是2的n次方，只有这样才能使得，取余简化
    // k % 2^n = k & (2^n - 1)
    table *remote_addr_data = newTable(64);
    table *remote_user_data = newTable(64);
    table *time_local_data = newTable(64);
    table *request_line_data = newTable(64);
    table *status_data = newTable(64);
    table *http_referer_data = newTable(64);
    table *http_user_agent_data = newTable(64);
    table *http_x_forwarded_for_data = newTable(64);
    table *http_sent_data = newTable(64);
    unsigned int total_bytes_sent = 0;
    unsigned int total_lines = 0;

    while (fgets(s, sizeof s, fp) != NULL)
    {
        int offset = 0;
        char value[8192] = {0};
        int len = strlen(s);

        char *remote_addr;
        char *remote_user;
        char *time_local;
        char *request_line;
        char *status_code;
        int body_bytes_sent;
        char *http_referer;
        char *http_user_agent;
        char *http_x_forwarded_for;

        if (parse_remote_addr(s, &offset, len, value) < 0)
        {
            goto error_line;
        }
        remote_addr = malloc(strlen(value));
        strcpy(remote_addr, value);
        if (parse_remote_user(s, &offset, len, value) < 0)
        {
            goto error_line;
        }
        remote_user = malloc(strlen(value));
        strcpy(remote_user, value);
        if (parse_time_local(s, &offset, len, value) < 0)
        {
            goto error_line;
        }
        time_local = malloc(strlen(value));
        strcpy(time_local, value);
        if (parse_request_line(s, &offset, len, value) < 0)
        {
            goto error_line;
        }
        request_line = malloc(strlen(value));
        strcpy(request_line, value);
        if (parse_status_code(s, &offset, len, value) < 0)
        {
            goto error_line;
        }
        status_code = malloc(strlen(value));
        strcpy(status_code, value);
        if (parse_body_bytes_sent(s, &offset, len, value) < 0)
        {
            goto error_line;
        }
        // TODO may malloc
        body_bytes_sent = atoi(value);
        if (parse_http_referer(s, &offset, len, value) < 0)
        {
            goto error_line;
        }
        http_referer = malloc(strlen(value));
        strcpy(http_referer, value);
        if (parse_http_user_agent(s, &offset, len, value) < 0)
        {
            goto error_line;
        }
        http_user_agent = malloc(strlen(value));
        strcpy(http_user_agent, value);
        if (parse_http_x_forwarded_for(s, &offset, len, value) < 0)
        {
            goto error_line;
        }
        http_x_forwarded_for = malloc(strlen(value));
        strcpy(http_x_forwarded_for, value);
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

        continue;

    error_line:
        free(remote_addr);
        free(remote_user);
        free(time_local);
        free(request_line);
        free(status_code);
        free(http_referer);
        free(http_user_agent);
        free(http_x_forwarded_for);
        fprintf(stderr, "%s", s);
    }

    // 分析完毕后，排序然后，打印统计数据

    char str_sent[1024];
    byteFormat(total_bytes_sent, str_sent);
    loop(status_data);
    unsigned int ip_count = 11;
    printf("\n共计\e[1;34m%u\e[00m次访问\n发送总流量\e[1;32m%s\e[00m\n独立IP数\e[1;31m%u\e[00m\n", total_lines, str_sent, ip_count);
    return 0;
}
