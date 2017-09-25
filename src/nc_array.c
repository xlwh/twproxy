/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>

#include <nc_core.h>

//创建一个数组
struct array * array_create(uint32_t n, size_t size)
{
    struct array *a;

    //进行断言判断
    ASSERT(n != 0 && size != 0);

    //给数组分配空间，调用自定义的内存分配函数来进行内存的分配
    a = nc_alloc(sizeof(*a));
    if (a == NULL) {
        return NULL;
    }

    //给数组元素分配空间
    a->elem = nc_alloc(n * size);
    if (a->elem == NULL) {
        nc_free(a);
        return NULL;
    }

    //初始化size等属性
    a->nelem = 0;
    a->size = size;
    a->nalloc = n;

    //返回创建好的数组
    return a;
}

//销毁一个数组，调用array_deinit和nc_free进行处理
void array_destroy(struct array *a)
{
    array_deinit(a);
    nc_free(a);
}

//数组初始化,可以指定申请空间的大小和size
rstatus_t array_init(struct array *a, uint32_t n, size_t size)
{
    ASSERT(n != 0 && size != 0);

    a->elem = nc_alloc(n * size);
    if (a->elem == NULL) {
        return NC_ENOMEM;
    }

    a->nelem = 0;
    a->size = size;
    a->nalloc = n;

    return NC_OK;
}

//清理数组里面的元素，调用nc_free
void array_deinit(struct array *a)
{
    ASSERT(a->nelem == 0);

    if (a->elem != NULL) {
        nc_free(a->elem);
    }
}

//根据emem定位数组坐标
uint32_t array_idx(struct array *a, void *elem)
{
    uint8_t *p, *q;
    uint32_t off, idx;

    //断言失败是否会退出？
    ASSERT(elem >= a->elem);

    p = a->elem;
    q = elem;
    off = (uint32_t)(q - p);

    ASSERT(off % (uint32_t)a->size == 0);

    idx = off / (uint32_t)a->size;

    return idx;
}

//往数组里面写入一个新的东西
void * array_push(struct array *a)
{
    void *elem, *new;
    size_t size;

    if (a->nelem == a->nalloc) {

        /* the array is full; allocate new array */
        size = a->size * a->nalloc;
        new = nc_realloc(a->elem, 2 * size);
        if (new == NULL) {
            return NULL;
        }

        a->elem = new;
        a->nalloc *= 2;
    }

    elem = (uint8_t *)a->elem + a->size * a->nelem;
    a->nelem++;

    return elem;
}

void *
array_pop(struct array *a)
{
    void *elem;

    ASSERT(a->nelem != 0);

    a->nelem--;
    elem = (uint8_t *)a->elem + a->size * a->nelem;

    return elem;
}

void *
array_get(struct array *a, uint32_t idx)
{
    void *elem;

    ASSERT(a->nelem != 0);
    ASSERT(idx < a->nelem);

    elem = (uint8_t *)a->elem + (a->size * idx);

    return elem;
}

void *
array_top(struct array *a)
{
    ASSERT(a->nelem != 0);

    return array_get(a, a->nelem - 1);
}

void
array_swap(struct array *a, struct array *b)
{
    struct array tmp;

    tmp = *a;
    *a = *b;
    *b = tmp;
}

/*
 * Sort nelem elements of the array in ascending order based on the
 * compare comparator.
 */
void
array_sort(struct array *a, array_compare_t compare)
{
    ASSERT(a->nelem != 0);

    qsort(a->elem, a->nelem, a->size, compare);
}

/*
 * Calls the func once for each element in the array as long as func returns
 * success. On failure short-circuits and returns the error status.
 */
rstatus_t
array_each(struct array *a, array_each_t func, void *data)
{
    uint32_t i, nelem;

    ASSERT(array_n(a) != 0);
    ASSERT(func != NULL);

    //变量数组
    for (i = 0, nelem = array_n(a); i < nelem; i++) {
        void *elem = array_get(a, i);
        rstatus_t status;

        //对每个函数调用自定义的处理函数
        status = func(elem, data);
        if (status != NC_OK) {
            return status;
        }
    }

    return NC_OK;
}
