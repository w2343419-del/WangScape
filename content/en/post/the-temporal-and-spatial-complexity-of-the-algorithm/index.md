---
pinned: false
tags:
    - Time Complexity
    - Space Complexity
categories:
    - Algorithm
title: "Time and Space Complexity"
description: "Complete Guide to Algorithmic Complexity - Time, Space, and Asymptotic Time Complexity"
date: 2026-03-09T10:32:00+08:00
image: ""
math: true
license: ""
hidden: false
comments: true
draft: false
ws_sync_zh_hash: "f7d9686bbbbea99fba6d53173f0cb7a65aecae43400b94305fcb436760ab645e"
---# Complete Guide to Algorithmic Complexity - Time, Space, and Asymptotic Time Complexity

Complexity analysis is a core tool for measuring algorithmic efficiency, helping us to anticipate performance bottlenecks before writing code. This article systematically explains the time complexity, space complexity, and the meaning and application of the three progressive symbols $ O $, $\ Omega $, and $\ Theta $, and explains them with a complete sample.

---

## 什么是复杂度

When we evaluate an algorithm, we can't just look at whether it can get the right results, but also how it performs when * * the amount of data increases * *. Complexity is a mathematical tool used to describe "the changing trend of the resources required by the algorithm as it grows with the input size $ n $".

- * * Time complexity * *: how many steps does the algorithm take?
- * * Space complexity * *: How much additional memory does the algorithm take up?

Both are expressed using * * progressive symbols * * - ignoring constant coefficients and focusing only on growth trends. The calculation rules are as follows:

- Keep only the highest sub-item: $3n ^ 2 + 2n + 1\ Rightarrow O (n ^ 2) $
- Ignore constant coefficient: $5n\ Rightarrow O (n) $
- Loop nested multiplication: $ n $ runs on both levels $\ Rightarrow O (n ^ 2) $
- Max sequential structure: $ O (n) + O (n ^ 2)\ Rightarrow O (n ^ 2) $

---

## 三种渐进时间复杂度

The same algorithm may behave very differently under different inputs. The three asymptotic time complexity describes the behavioral boundaries of the algorithm from three angles: * * upper bound, lower bound, and tight bound * *.

### 大 O 符号（上界，最坏情况）

* * Mathematical definition * *: there are constants $ c > 0$ and $ n_0$, when $ n\ geq n_0$, there is always:

$ $ f (n)\ leq c\ cdot g (n) $ $

The running time of the algorithm * * up to * * is a constant multiple of $ g (n) $, which is the * * cap commitment * * of the growth rate - guarantee not to be slower than this. The most widely used in everyday development, saying "this algorithm is $ O (n ^ 2) $" usually refers to the worst-case scenario.

__ code_block_0 __

### 大 Ω 符号（下界，最好情况）

* * Mathematical definition * *: there are constants $ c > 0$ and $ n_0$, when $ n\ geq n_0$, there is always:

$ $ f (n)\ geq c\ cdot g (n) $ $

The running time of the algorithm * * at least * * is a constant multiple of $ g (n) $, which is the * * lower bound commitment * * of the growth rate - guaranteed not to be faster than this.

__ code_block_1 __

Classic conclusion: Any * * comparison-based sorting algorithm * *, the lower bound is $\ Omega (n\ log n) $, which is the mathematically provable limit and cannot be broken.

### 大 Θ 符号（紧确界，精确描述）

* * Mathematical definition * *: there are constants $ c_1, c_2 > 0$ and $ n_0$, when $ n\ geq n_0$, there is always:

$ $ c_1\ cdot g (n)\ leq f (n)\ leq c_2\ cdot g (n) $ $

The algorithm is clamped by $ g (n) $ from the * * top and bottom sides at the same time * *, which is the most accurate description. $\ Theta $ holds if and only if $ O $ and $\ Omega $ hold together and have the same order.

__ code_block_2 __

### 三种符号对比

| Symbols | Meaning | Intuitive Memory | Linear Find Example |
|------|------|----------|-------------|
| $ O (g) $ | Upper bound | Slowest not exceeding this speed | $ O (n) $, worst traversal all |
| $\ Omega (g) $ | Lower bound | Fastest not less than this speed | $\ Omega (1) $, best found first |
| $\ Theta (g) $ | Exact | This speed | Does not exist (upper and lower levels) |

There is no $\ Theta $ for linear search, because it is better to be different from the worst case order, and the upper and lower bounds cannot be closed.

---

## 时间复杂度

Time complexity description algorithm * * Number of steps executed * * Growth trend with input size $ n $.

### 常见阶数对比

| Complexity | Name | Typical Scenario | $ n = magnitude at 10 ^ 6$ |
|--------|------|----------|-------------------|
| $ O (1) $ | Constant time | Array access by subscript, hash table lookup | 1 time |
| $ O (\ log n) $ | Logarithmic time | Binary lookup, balanced binary tree operations | ~ 20 times |
| $ O (n) $ | Linear time | Traversal array, linear lookup | $10 ^ 6$ times |
| $ O (n\ log n) $ | Linear logarithm | Merge sort, heap sort | ~ $2\ times 10 ^ 7$ times |
| $ O (n ^ 2) $ | square time | bubbling sort, select sort | $10 ^ {12} $ times ⚠️ |
| $ O (2 ^ n) $ | Exponential time | Violent recursive subset enumeration | Not acceptable 🚫 |

Growth rate: $ O (1) < O (\ log n) < O (n) < O (n\ log n) < O (n ^ 2) < O (2 ^ n) $

### 代码示例

__ code_block_3 __

---

## 空间复杂度

The spatial complexity describes the growth trend of the * * additional memory usage * * with the input scale (excluding the input data itself) when the algorithm is running.

### 常见阶数对比

| Complexity | Meaning | Typical Scenario |
|--------|------|----------|
| $ O (1) $ | Fixed space | Sort in place, with a few temporary variables |
| $ O (\ log n) $ | Logarithmic space | Recursive call stack (binary, fast average) |
| $ O (n) $ | Linear space | Copy array, hash table, BFS queue |
| $ O (n ^ 2) $ | Square Space | Create $ n\ times n $ Matrix, Adjacency Matrix |

### 代码示例

__ code_block_4 __

Each recursive function call allocates a stack frame on the call stack, and the * * recursive depth is the space complexity * *. Deep recursion can lead to stack overflow in extreme cases.

---

## 综合样例分析：两数之和

Complete the analysis of the three progressive symbols and spatio-temporal complexity with a classical problem.

## 问题

### 问题描述

Given the integer array `arr` and the target value `target`, find the subscript * * for the two numbers in the array * * and `target`. There is only one answer per input and the same element cannot be used twice.

### 输入输出

- Input: `arr = [2, 7, 11, 15]`, `target = 9`
- Output: `[0, 1]`

### 约束条件

- $2\ leq n\ leq 10 ^ 4$
- $ -10 ^ 9\ leq arr [i]\ leq10 ^ 9$
- Guaranteed and only one answer

## 思路分析

### 解法一：暴力枚举

Enumerate all pairs of numbers $ (i, j) $ and check if `arr [i] + arr [j] = = target` is met. Direct thinking, no extra space needed, but time inefficient.

### 解法二：哈希表优化

When an array is traversed, values that have already been seen are stored in the hash table. For each element, check if its * * complement * * (`target - arr [i]`) is already in the table. Returns directly if hit, otherwise table the current element.

This is typical * * space for time * *: $ O (n) $ extra space, reducing time from $ O (n ^ 2) $ to $ O (n) $.

## 代码实现

### 解法一：暴力枚举

__ code_block_5 __

### 解法二：哈希表

__ code_block_6 __

## 复杂度与优缺点

### 解法一：暴力枚举

- Time: $ O (n ^ 2) $ (worst), $\ Omega (1) $ (best, hit first pair), none $\ Theta $
- Space: $\ Theta (1) $

- ✅ No extra space, memory friendly
- Simple ✅ implementation, no hash function required
- Poor ❌ time efficiency, $ n = 10 ^ 4$ has 100 million operations
- ❌ Not suitable for large scale data

### 解法二：哈希表

- Time: $\ Theta (n) $ (must be traversed once, hash lookup is $ O (1) $)
- Space: $\ Theta (n) $ (maximum of $ n $ elements in hash table)

- ✅ Time efficient, linear scan once
- ✅ Suitable for large scale data
- ❌ Extra $ O (n) $ memory required
- ❌ Hash collisions can degenerate in extreme cases

### 对比总结

| | Time (Worst) | Time (Best) | Time ($\ Theta $) | Space | Suggested Scenarios |
|--|-------------|-------------|-----------------|------|----------|
| Violent Enumeration | $ O (n ^ 2) $ | $\ Omega (1) $ | — | $ O (1) $ | Extremely Limited Memory |
| Hashtable | $ O (n) $ | $\ Omega (n) $ | $\ Theta (n) $ | $ O (n) $ | General Business Systems |

---

## 时间与空间的权衡

In actual engineering, time and space are often * * not optimal * * at the same time, and trade-offs need to be made according to the scene.

- * * Spaces for time * * (most common): hash tables, caches, dynamically planned memorized arrays.
- * * Swap time for space * *: Read large files line by line while streaming, avoiding loading all data into memory at once.

| Scenarios | Recommendation Strategies |
|------|----------|
| Real-time response, high concurrency systems | Sacrificing space, optimizing time |
| Embedded Devices, Memory-Constrained Environments | Sacrifice Time, Save Space |
| General business systems | Prioritize optimizing time, space is sufficient |

---

## 常见算法复杂度速查

| Algorithm | Time ($O$) | Time ($\Omega$) | Time ($\Theta$) | Space |
|------|------------|------------------|------------------|------|
| Array access | $O(1)$ | $\Omega(1)$ | $\Theta(1)$ | $O(1)$ |
| Linear search | $O(n)$ | $\Omega(1)$ | — | $O(1)$ |
| Binary search | $O(\log n)$ | $\Omega(1)$ | — | $O(1)$ |
| Bubble sort | $O(n^2)$ | $\Omega(n)$ | $\Theta(n^2)$ | $O(1)$ |
| Merge sort | $O(n \log n)$ | $\Omega(n \log n)$ | $\Theta(n \log n)$ | $O(n)$ |
| Quick sort | $O(n^2)$ | $\Omega(n \log n)$ | — | $O(\log n)$ |
| Hash table lookup | $O(n)$ | $\Omega(1)$ | — | $O(n)$ |

There is no $\ Theta $ for quick sorting and linear searching, because it is better to be different from the worst case order, and the upper and lower bounds cannot be closed.

---