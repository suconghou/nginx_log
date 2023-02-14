
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct tableItem
{
    char *key;
    unsigned int value;
    unsigned int hcode; // 在hash表扩容时比较有用，不必再次对key进行hash了
} tableItem;

typedef struct table
{
    tableItem **dataArr;  // 数组类型，每个成员都是 【 tableItem * 】类型
    unsigned int counter; // 实际存储的成员数量
    unsigned int dataLen; // 数组的卡槽数量
} table;

// fnv1a32
#define FNV_PRIME_32 16777619
#define FNV_OFFSET_32 2166136261U
static inline unsigned int hash(const char *s)
{
    unsigned int hash = FNV_OFFSET_32, i;
    for (i = 0; i < strlen(s); i++)
    {
        hash = hash ^ (s[i]);       // xor next byte into the bottom of the hash
        hash = hash * FNV_PRIME_32; // Multiply by prime number found to work well
    }
    return hash;
}

// 必须是2的n次方
table *newTable(int n)
{
    table *t = (table *)malloc(sizeof(table));
    t->dataArr = (tableItem **)calloc(n, sizeof(tableItem *));
    t->counter = 0;
    t->dataLen = n;
    return t;
}

unsigned int forEach(table *t)
{
    unsigned int len = t->dataLen;
    unsigned int num = 0;
    for (int i = 0; i < len; i++)
    {
        if (t->dataArr[i] != NULL)
        {
            num++;
            // printf("%d key:%s,value:%d,hcode:%u\n", i, t->dataArr[i]->key, t->dataArr[i]->value, t->dataArr[i]->hcode);
        }
    }
    return num;
}

// 无需手动调用，会自动检测需要时，自动调用
static inline void _enlarge(table *t)
{
    unsigned int l = t->dataLen;
    unsigned int num = t->counter;
    tableItem **data = (tableItem **)calloc(l * 2, sizeof(tableItem *));
    unsigned int maxHash = l * 2 - 1;
    for (int i = 0; i < l && num > 0; i++)
    {
        if (t->dataArr[i] != NULL)
        {
            // 旧插槽有数据，则需要移动
            unsigned int j = t->dataArr[i]->hcode & maxHash;
            while (data[j] != NULL)
            {
                j = (j + 1) & maxHash;
            }
            data[j] = t->dataArr[i];
            num--;
        }
    }
    free(t->dataArr);
    t->dataArr = data;
    t->dataLen = l * 2;
}

// 如果返回值>=0，代表是更新， 否则为新增
// 我们可以更具此返回值，如果是更新则传入的key再堆上分配内存，可以free掉
int incr(table *t, char *key, int n)
{
    // 按照nim的内部实现，存储的成员数已达插槽数量的三分之二或者空闲的插槽不足4个
    // 则必须扩容
    if (t->dataLen * 2 < t->counter * 3 || t->dataLen - t->counter < 4)
    {
        _enlarge(t);
    }
    // 扩容后dataLen将会变化，之前存储的成员都会移动
    unsigned int maxHash = t->dataLen - 1; // 使用异或快速计算的参数，代表插槽数量-1
    unsigned int hc = hash(key);
    unsigned int h = hc & maxHash; // 计算应落到哪个插槽
    while (t->dataArr[h] != NULL)
    {
        // 如果插槽非空，判断是否是对应的key，是则更新
        // 否则，hash碰撞或者取余落到相同卡槽，但不是这个key,需要计算下一个卡槽，判断下个卡槽的情况
        if (t->dataArr[h]->hcode == hc && strcmp(t->dataArr[h]->key, key) == 0)
        {
            t->dataArr[h]->value += n;
            return h;
        }
        // nim 中使用此策略，计算下一个插槽位置，其实就是连续的插槽往下探测
        h = (h + 1) & maxHash;
        // 此算法计算出下一个卡槽的index,我们上面检测了必然有空闲的插槽，一旦遇到空闲的插槽，循环中断
        // 此时我们就新插入这个值到这个插槽
    }
    tableItem *item = malloc(sizeof(tableItem));
    item->key = key;
    item->value = n;
    item->hcode = hc;
    t->dataArr[h] = item;
    t->counter++;
    return -1;
}

// 插入排序,倒序
// 排序过后不应该在新增数据到table了
tableItem **sort22(table *t)
{
    int num = t->counter;
    tableItem **data = (tableItem **)calloc(num, sizeof(tableItem *));
    int index = 0;
    for (int i = 0; i < t->dataLen && index < num; i++)
    {
        if (t->dataArr[i] != NULL)
        {
            data[index] = t->dataArr[i];
            index++;
        }
    }
    free(t->dataArr);
    free(t);
    // 然后使用希尔排序
    int gap, i, j;
    tableItem *temp;
    for (gap = num >> 1; gap > 0; gap >>= 1)
    {
        for (i = gap; i < num; i++)
        {
            temp = data[i];
            for (j = i - gap; j >= 0 && data[j]->value < temp->value; j -= gap)
            {
                data[j + gap] = data[j];
            }
            data[j + gap] = temp;
        }
    }
    return data;
}

static inline int compare_function(const void *a, const void *b)
{
    // 注意，这里不是 tableItem *x = (tableItem *)a;
    tableItem *x = *(tableItem **)a;
    tableItem *y = *(tableItem **)b;
    return (y->value - x->value) - (x->value - y->value);
}

// 插入排序,倒序
// 排序过后不应该在新增数据到table了
tableItem **sort(table *t)
{
    int num = t->counter;
    tableItem **data = (tableItem **)calloc(num, sizeof(tableItem *));
    int index = 0;
    for (int i = 0; i < t->dataLen && index < num; i++)
    {
        if (t->dataArr[i] != NULL)
        {
            data[index] = t->dataArr[i];
            index++;
        }
    }
    free(t->dataArr);
    free(t);
    qsort(data, num, sizeof(tableItem *), &compare_function);
    return data;
}