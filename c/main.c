#include <stdio.h>
#include <string.h>

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
    if (x == 34 && y == 32 && (z == 50 || z == 49 || z == 48))
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

int main()
{
    FILE *fp = fopen("/tmp/1", "r");
    if (fp == NULL)
    {
        return -1;
    }
    char s[8192];
    int linecount = 0;
    while (fgets(s, sizeof s, fp) != NULL)
    {
        int offset = 0;
        char value[8192] = {0};
        int len = strlen(s);
        int a = parse_remote_addr(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("remote_addr:%s\n", value);

        a = parse_remote_user(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("remote_user:%s\n", value);

        a = parse_time_local(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("time_local:%s\n", value);

        a = parse_request_line(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("request_line:%s\n", value);

        a = parse_status_code(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("status_code:%s\n", value);

        a = parse_body_bytes_sent(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("body_bytes_sent:%s\n", value);

        a = parse_http_referer(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("http_referer:%s\n", value);

        a = parse_http_user_agent(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("http_user_agent:%s\n", value);

        a = parse_http_x_forwarded_for(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("http_x_forwarded_for:%s\n", value);

        a = parse_host(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("host:%s\n", value);

        a = parse_request_length(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("request_length:%s\n", value);

        a = parse_bytes_sent(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("bytes_sent:%s\n", value);

        a = parse_upstream_addr(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("upstream_addr:%s\n", value);

        a = parse_upstream_status(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("upstream_status:%s\n", value);

        a = parse_request_time(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("request_time:%s\n", value);

        a = parse_upstream_response_time(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("upstream_response_time:%s\n", value);

        a = parse_upstream_connect_time(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("upstream_connect_time:%s\n", value);

        a = parse_upstream_header_time(s, &offset, len, value);
        printf("offset:%d\n", offset);
        printf("index:%d\n", a);
        printf("upstream_header_time:%s\n", value);
    }

    return 0;
}
