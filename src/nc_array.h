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

#ifndef _NC_ARRAY_H_
#define _NC_ARRAY_H_

#include <nc_core.h>

typedef int (*array_compare_t)(const void *, const void *);
typedef rstatus_t (*array_each_t)(void *, void *);

//自定义的数组的结构
struct array {
    uint32_t nelem;  /* # element */
    void     *elem;  /* element */
    size_t   size;   /* element size */
    uint32_t nalloc; /* # allocated element */   //数组总的大小
};

#define null_array { 0, NULL, 0, 0 }

//创建一个空数组
static inline void array_null(struct array *a)
{
    a->nelem = 0;
    a->elem = NULL;
    a->size = 0;
    a->nalloc = 0;
}

//对一个数组进行设置
static inline void
array_set(struct array *a, void *elem, size_t size, uint32_t nalloc)
{
    a->nelem = 0;
    a->elem = elem;
    a->size = size;
    a->nalloc = nalloc;
}

//计算数组中有多少个元素
static inline uint32_t
array_n(const struct array *a)
{
    return a->nelem;
}

//创建一个数组
struct array *array_create(uint32_t n, size_t size);
//销毁一个数组
void array_destroy(struct array *a);
//对一个数组进行初始化
rstatus_t array_init(struct array *a, uint32_t n, size_t size);
void array_deinit(struct array *a);

//返回一个元素在数组上的index
uint32_t array_idx(struct array *a, void *elem);
//加入元素
void *array_push(struct array *a);
//弹出元素
void *array_pop(struct array *a);
//给定index，获取元素
void *array_get(struct array *a, uint32_t idx);
void *array_top(struct array *a);
//交换两个元素
void array_swap(struct array *a, struct array *b);
//对整个数组进行排序
void array_sort(struct array *a, array_compare_t compare);
//传入一个函数，对每个元素进行处理
rstatus_t array_each(struct array *a, array_each_t func, void *data);

#endif
