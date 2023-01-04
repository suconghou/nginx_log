
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct tableItem
{
    char *key;
    unsigned int value;
    unsigned int hcode;
} tableItem;

typedef struct table
{
    tableItem **dataArr;
    int counter;
    int dataLen;
} table;

unsigned int hash(char *str)
{
    register unsigned int h;
    register unsigned char *p;
    for (h = 0, p = (unsigned char *)str; *p; p++)
    {
        h = 31 * h + *p;
    }
    return h;
}

table *newTable(int n)
{
    table *t = (table *)malloc(sizeof(table));
    t->dataArr = (tableItem **)calloc(n, sizeof(tableItem));
    t->counter = 0;
    t->dataLen = n;
    return t;
}

void _enlarge(table *t)
{
    unsigned int l = t->dataLen;
    tableItem **data = (tableItem **)calloc(l * 2, sizeof(tableItem));
    unsigned int maxHash = l * 2 - 1;
    for (int i = 0; i < l; i++)
    {
        if (t->dataArr[i] != NULL)
        {
            printf("move key:%s,value:%d,hcode:%d\n", t->dataArr[i]->key, t->dataArr[i]->value, t->dataArr[i]->hcode);
            unsigned int h = t->dataArr[i]->hcode & maxHash;
            if (data[h] != NULL)
            {
                h = (t->dataArr[i]->hcode + 1) & maxHash;
            }
            data[h] = t->dataArr[i];
        }
    }
    t->dataArr = data;
    t->dataLen = l * 2;
}

int incr(table *t, char *key)
{
    if (t->dataLen * 2 < t->counter * 3 || t->dataLen - t->counter < 4)
    {
        _enlarge(t);
        return 1;
    }
    unsigned int maxHash = t->dataLen ;
    unsigned int hc = hash(key);
    unsigned int h = hc % maxHash;
    printf("maxHash:%d\n", maxHash);
    int i = 0;
    while (t->dataArr[h] != NULL)
    {
        printf("loop:%s,hcode:%d,try %d \n", t->dataArr[h]->key, t->dataArr[h]->hcode, h);
        if (t->dataArr[h]->hcode == hc && strcmp(t->dataArr[h]->key, key) == 0)
        {
            t->dataArr[h]->value++;
            return h;
        }
        h = (hc + 1) % maxHash;
        if (i++ > 40)
        {
            exit(0);
        }
    }
    tableItem *item = malloc(sizeof(tableItem));
    item->key = strdup(key);
    item->value = 1;
    item->hcode = hc;
    t->dataArr[h] = item;
    t->counter++;
    return 0;
}

void loop(table *t)
{
    unsigned int len = t->dataLen;
    for (int i = 0; i < len; i++)
    {
        if (t->dataArr[i] != NULL)
        {
            printf("key:%s,value:%d,hcode:%d\n", t->dataArr[i]->key, t->dataArr[i]->value, t->dataArr[i]->hcode);
        }
    }
}