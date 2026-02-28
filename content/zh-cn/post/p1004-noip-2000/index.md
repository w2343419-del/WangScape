---
tags:
    - 算法
categories:
    - 算法
pinned: false
title: "P1004 [NOIP 2000 提高组] 方格取数 分析与总结"
description: "date: 2026-02-28T11:31:04+08:00"
date: 2026-02-28T11:31:00+08:00
image: ""
math: false
license: ""
hidden: false
comments: true
draft: false
---
这是一道经典但具有一定难度的棋盘模型题，虽然是 2000 年的 NOIP 题目，但作为压轴，对于像我这样第一次接触的人来说，还是相当困难的。

先看题目背景

NOIP 2000 提高组 T4

题目描述

设有 N×N 的方格图 (N≤9)，我们将其中的某些方格中填入正整数，而其他的方格中则放入数字 0。
某人从图的左上角的 A 点（0，0）出发，可以向下行走，也可以向右走，直到到达右下角的 B 点（N, N)。在走过的路上，他可以取走方格中的数（取走后的方格中将变为数字 0）。
此人从 A 点到 B 点共走两次，试找出 2 条这样的路径，使得取得的数之和为最大。

输入格式

输入的第一行为一个整数 N（表示 N×N 的方格图），接下来的每行有三个整数，前两个表示位置，第三个数为该位置上所放的数。一行单独的 0 表示输入结束。

输出格式

只需输出一个整数，表示 2 条路径上取得的最大的和。


输入输出样例

输入

8

2 3 13

2 6  6

3 5  7

4 4 14

5 2 21

5 6  4

6 3 15

7 2 14

0 0  0


输出
67


说明/提示

数据范围：1≤N≤9。


我一开始尝试是选择的先进行一轮枚举，然后再对已进行了更改的 matrix 进行再一次的枚举（就是模拟取数），但是发现难度有点过大。最后实在想不出来解决方法了，找了 Claude，它给出的解决方法是采用 dp 算法（详见解法一），我又想到了 DFS 结合剪枝的算法（感谢自己之前做的走迷宫问题，那是一道有关最少步数的算法题，刚好适用于 DFS 结合剪枝）（详见解法二），随后 Claude 还给出了一个适用于一般解的算法————费用流解法（难度过大，属于超纲解法，略写一二，详见解法三）。

ps. 解释一下为什么不能采取两次枚举。一次路径会改变地图，影响第二次，所以两条路径必须联动考虑。

解法一（dp 动态规划）：

核心思想：将两条路径同步推进，用一个DP同时模拟两个人的行走。

状态设计：设 dp[k][x1][x2]，其中：

k 为当前走的步数（即 x + y 的值，从2到2N）

x1、x2 分别为两人当前所在的行号

由 k 和 x 可以推出 y = k - x（关键，这一步降低了维度），因此列号不需要单独存储

去重处理：当两人在同一格时（x1 == x2，则 y1 == y2），该格只取一次。

转移：每步两人各自可以选择向右或向下，共4种组合。


完整代码
```c
#include <stdio.h>

int N;
int map[10][10];
int dp[20][10][10]; // dp[步数][人1的行][人2的行]

int main() {
    scanf("%d", &N);

    int x, y, v;
    while (scanf("%d %d %d", &x, &y, &v) && (x || y || v))
        map[x][y] = v;

    // 初始化为-1表示不可达
    for (int k = 0; k < 20; k++)
        for (int i = 0; i < 10; i++)
            for (int j = 0; j < 10; j++)
                dp[k][i][j] = -1;

    dp[2][1][1] = map[1][1];

    // 动态规划主循环
    for (int k = 2; k < 2 * N; k++) {
        for (int x1 = 1; x1 <= N; x1++) {
            int y1 = k - x1;
            if (y1 < 1 || y1 > N) continue;

            for (int x2 = x1; x2 <= N; x2++) {
                int y2 = k - x2;
                if (y2 < 1 || y2 > N) continue;
                if (dp[k][x1][x2] < 0) continue;

                // 尝试所有4种移动组合
                for (int m1 = 0; m1 <= 1; m1++) {
                    for (int m2 = 0; m2 <= 1; m2++) {
                        int nx1 = x1 + m1,     ny1 = y1 + (1 - m1);
                        int nx2 = x2 + m2,     ny2 = y2 + (1 - m2);

                        if (nx1 > N || ny1 > N) continue;
                        if (nx2 > N || ny2 > N) continue;

                        // 计算当前步收益
                        int gain = map[nx1][ny1];
                        if (nx1 != nx2) gain += map[nx2][ny2];

                        // 规范化：保证 a <= b
                        int a = nx1, b = nx2;
                        if (a > b) { int t = a; a = b; b = t; }

                        int newval = dp[k][x1][x2] + gain;
                        if (newval > dp[k + 1][a][b])
                            dp[k + 1][a][b] = newval;
                    }
                }
            }
        }
    }

    printf("%d\n", dp[2 * N][N][N]);
    return 0;
}
```

时间复杂度：O(N³)


解法二（DFS + 剪枝）：

核心思想：类似于 dp 算法（毕竟深搜和 dp 本质上就是一个东西），但添加了记忆化搜索这一步，避免了重复搜索。（若无记忆化搜索，计算量将是指数级爆炸，在 N=9 时约为 4^16 次）

完整代码
```c
#include <stdio.h>
#include <string.h>

int N;
int map[10][10];
int memo[20][10][10];    // 记忆化数组
int visited[20][10][10]; // 标记是否计算过

int dfs(int k, int x1, int x2) {
    if (x1 == N && x2 == N) return 0;

    if (visited[k][x1][x2]) return memo[k][x1][x2];
    visited[k][x1][x2] = 1;

    int y1 = k - x1;
    int y2 = k - x2;
    int best = -1;

    for (int m1 = 0; m1 <= 1; m1++) {
        for (int m2 = 0; m2 <= 1; m2++) {
            int nx1 = x1 + m1,  ny1 = y1 + (1 - m1);
            int nx2 = x2 + m2,  ny2 = y2 + (1 - m2);

            if (nx1 > N || ny1 > N) continue;
            if (nx2 > N || ny2 > N) continue;

            int a = nx1, b = nx2;
            if (a > b) { int t = a; a = b; b = t; }

            int sub = dfs(k + 1, a, b);
            if (sub < 0) continue;

            int gain = map[nx1][ny1];
            if (nx1 != nx2) gain += map[nx2][ny2];

            if (gain + sub > best) best = gain + sub;
        }
    }

    memo[k][x1][x2] = best;
    return best;
}

int main() {
    scanf("%d", &N);

    int x, y, v;
    while (scanf("%d %d %d", &x, &y, &v) && (x || y || v))
        map[x][y] = v;

    memset(visited, 0, sizeof(visited));

    int start_val = map[1][1];
    int result = dfs(2, 1, 1);

    printf("%d\n", result >= 0 ? start_val + result : 0);
    return 0;
}
```

时间复杂度：O(N³)


解法三（费用流解法）：

核心思想：将"两条路径取最大值"转化为网络流问题。

建模思路
关键观察：
两条从 A 到 B 的路径 = 从源点到汇点流量为 2 的流
每个格子最多取一次 = 每个节点容量为 1
取得数字最大 = 费用最大（转为最小费用取负值）

拆点： 每个格子 (i,j) 拆成两个节点 in 和 out：
in → out：容量 1，费用 -map[i][j]（取负是因为求最小费用）
in → out：再加一条容量 1，费用 0（允许第二条路径经过但不重复取值）
即：合并为容量 2，但只有第一单位流有收益

连边： (i,j) 的 out 连向 (i+1,j) 的 in 和 (i,j+1) 的 in，容量 2，费用 0。

源汇： 源点 S 连 (1,1).in，(N,N).out 连汇点 T，流量均为 2。

每个格子(i,j)拆点后: 容量1，费用-val (第一条路经过，取走数字)
in(i,j) ================> out(i,j) 容量1，费用0 (第二条路经过，数字已取走)


完整代码（MCMF，SPFA实现）
```c
#include <stdio.h>
#include <string.h>

#define MAXN 1000
#define MAXE 10000
#define INF  0x3f3f3f3f

int head[MAXN], nxt[MAXE], to[MAXE], cap[MAXE], cost[MAXE], tot;

void init() {
    memset(head, -1, sizeof(head));
    tot = 0;
}

void add_edge(int u, int v, int c, int w) {
    to[tot] = v; cap[tot] = c; cost[tot] = w; nxt[tot] = head[u]; head[u] = tot++;
    to[tot] = u; cap[tot] = 0; cost[tot] = -w; nxt[tot] = head[v]; head[v] = tot++;
}

int dist[MAXN], in_queue[MAXN], prevv[MAXN], preve[MAXN];
int queue[MAXN * 100];

int spfa(int s, int t, int n) {
    memset(dist, 0x3f, sizeof(int) * (n + 1));
    memset(in_queue, 0, sizeof(int) * (n + 1));
    dist[s] = 0;

    int front = 0, rear = 0;
    queue[rear++] = s;
    in_queue[s] = 1;

    // SPFA主循环
    while (front != rear) {
        int u = queue[front++];
        in_queue[u] = 0;

        // 松弛边
        for (int e = head[u]; e != -1; e = nxt[e]) {
            if (cap[e] > 0 && dist[to[e]] > dist[u] + cost[e]) {
                dist[to[e]] = dist[u] + cost[e];
                prevv[to[e]] = u;
                preve[to[e]] = e;

                if (!in_queue[to[e]]) {
                    queue[rear++] = to[e];
                    in_queue[to[e]] = 1;
                }
            }
        }
    }

    return dist[t] < INF;
}

int mcmf(int s, int t, int n) {
    int total_cost = 0;

    while (spfa(s, t, n)) {
        int flow = INF;
        for (int v = t; v != s; v = prevv[v])
            if (cap[preve[v]] < flow) flow = cap[preve[v]];

        for (int v = t; v != s; v = prevv[v]) {
            cap[preve[v]] -= flow;
            cap[preve[v] ^ 1] += flow;
        }

        total_cost += dist[t] * flow;
    }

    return total_cost;
}

int main() {
    int N;
    scanf("%d", &N);

    int map[10][10] = {0};
    int x, y, v;
    while (scanf("%d %d %d", &x, &y, &v) && (x || y || v))
        map[x][y] = v;

    init();

    int S = 2 * N * N + 1;
    int T = 2 * N * N + 2;
    int total_nodes = T;

    #define IN(i,j)  ((i-1)*N+(j))
    #define OUT(i,j) (N*N+(i-1)*N+(j))

    for (int i = 1; i <= N; i++) {
        for (int j = 1; j <= N; j++) {
            if (map[i][j] > 0) {
                add_edge(IN(i,j), OUT(i,j), 1, -map[i][j]);
                add_edge(IN(i,j), OUT(i,j), 1, 0);
            } else {
                add_edge(IN(i,j), OUT(i,j), 2, 0);
            }

            if (j + 1 <= N) add_edge(OUT(i,j), IN(i,j+1), 2, 0);
            if (i + 1 <= N) add_edge(OUT(i,j), IN(i+1,j), 2, 0);
        }
    }

    add_edge(S, IN(1,1), 2, 0);
    add_edge(OUT(N,N), T, 2, 0);

    int ans = -mcmf(S, T, total_nodes);
    printf("%d\n", ans);
    return 0;
}
```

优势：可轻松扩展到 K 条路径。


