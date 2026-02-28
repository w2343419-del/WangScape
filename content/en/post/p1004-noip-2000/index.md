---
tags:
    - Algorithm
categories:
    - Algorithm
pinned: false
title: "P1004 [NOIP 2000 Advanced Group] Grid Number Picking: Analysis and Summary"
description: "A multi-solution analysis of a classic grid model problem: DP, DFS memoization, and MCMF"
date: 2026-02-28T11:31:00+08:00
image: ""
math: false
license: ""
hidden: false
comments: true
draft: false
ws_sync_zh_hash: "581e112e1c987d2c619154fd22488b7844362560c52f6e0033a14b1403f2a0e5"
---

This is a classic but challenging grid model problem. Even though it comes from NOIP 2000, it is still difficult for first-time solvers. In this post, I summarize three approaches from easy to hard: dynamic programming, DFS with memoization, and minimum-cost maximum-flow.

## Problem statement

Given an $N \times N$ grid ($N \le 9$), some cells contain positive integers and others contain 0.

Starting from the top-left corner and moving only right or down, a person reaches the bottom-right corner and can collect numbers from visited cells. Collected cells become 0. The person makes this trip twice. Find two paths that maximize the total collected sum.

### Input format

- The first line is integer $N$.
- Each following line contains three integers $(x, y, v)$ meaning cell $(x, y)$ has value $v$.
- A line `0 0 0` ends the input.

### Output format

- Output one integer: the maximum total sum collected by two paths.

### Sample

Input:

```text
8
2 3 13
2 6 6
3 5 7
4 4 14
5 2 21
5 6 4
6 3 15
7 2 14
0 0 0
```

Output:

```text
67
```

## Solution 1: Dynamic Programming

Core idea: advance two paths simultaneously and model them as two people walking at the same time.

State definition: `dp[k][x1][x2]`

- `k`: total step index ($x+y$)
- `x1`, `x2`: row indices of person 1 and person 2
- Then `y1 = k - x1`, `y2 = k - x2`

When both people are on the same cell, count that cell only once.

```c
#include <stdio.h>

int N;
int map[10][10];
int dp[20][10][10]; // dp[step][row1][row2]

int main() {
    scanf("%d", &N);

    int x, y, v;
    while (scanf("%d %d %d", &x, &y, &v) && (x || y || v))
        map[x][y] = v;

    // Initialize as unreachable
    for (int k = 0; k < 20; k++)
        for (int i = 0; i < 10; i++)
            for (int j = 0; j < 10; j++)
                dp[k][i][j] = -1;

    dp[2][1][1] = map[1][1];

    // ========== Dynamic programming main loop ==========
    for (int k = 2; k < 2 * N; k++) {
        for (int x1 = 1; x1 <= N; x1++) {
            int y1 = k - x1;
            if (y1 < 1 || y1 > N) continue;

            for (int x2 = x1; x2 <= N; x2++) {
                int y2 = k - x2;
                if (y2 < 1 || y2 > N) continue;
                if (dp[k][x1][x2] < 0) continue;

                // Try all 4 move combinations
                for (int m1 = 0; m1 <= 1; m1++) {
                    for (int m2 = 0; m2 <= 1; m2++) {
                        int nx1 = x1 + m1, ny1 = y1 + (1 - m1);
                        int nx2 = x2 + m2, ny2 = y2 + (1 - m2);

                        if (nx1 > N || ny1 > N) continue;
                        if (nx2 > N || ny2 > N) continue;

                        int gain = map[nx1][ny1];
                        if (nx1 != nx2) gain += map[nx2][ny2];

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

Time complexity: $O(N^3)$

## Solution 2: DFS + Memoization

Core idea: same state viewpoint as DP, but implemented with DFS and memoization to avoid repeated subproblems.

```c
#include <stdio.h>
#include <string.h>

// ========== DFS + memoization ==========

int N;
int map[10][10];
int memo[20][10][10];    // memoized results
int visited[20][10][10]; // computed flag

int dfs(int k, int x1, int x2) {
    if (x1 == N && x2 == N) return 0;

    if (visited[k][x1][x2]) return memo[k][x1][x2];
    visited[k][x1][x2] = 1;

    int y1 = k - x1;
    int y2 = k - x2;
    int best = -1;

    for (int m1 = 0; m1 <= 1; m1++) {
        for (int m2 = 0; m2 <= 1; m2++) {
            int nx1 = x1 + m1, ny1 = y1 + (1 - m1);
            int nx2 = x2 + m2, ny2 = y2 + (1 - m2);

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

Time complexity: $O(N^3)$

## Solution 3: Min-Cost Max-Flow (MCMF)

Core idea: convert “maximize value of two paths” into a flow optimization problem.

- Two paths from source to sink means total flow = 2
- Each cell can be collected at most once
- Maximum gain can be converted into minimum cost by negating value

Node splitting for each cell $(i,j)$:

- `in(i,j) -> out(i,j)`, capacity 1, cost `-value`
- `in(i,j) -> out(i,j)`, capacity 1, cost `0`

This allows two paths to pass, but only one can collect value.

```c
#include <stdio.h>
#include <string.h>

#define MAXN 1000
#define MAXE 10000
#define INF  0x3f3f3f3f

// ========== Forward-star graph structure ==========

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

// ========== SPFA ==========

int spfa(int s, int t, int n) {
    memset(dist, 0x3f, sizeof(int) * (n + 1));
    memset(in_queue, 0, sizeof(int) * (n + 1));
    dist[s] = 0;

    int front = 0, rear = 0;
    queue[rear++] = s;
    in_queue[s] = 1;

    while (front != rear) {
        int u = queue[front++];
        in_queue[u] = 0;

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

// ========== Min-cost max-flow ==========

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

Advantage: this model scales naturally to the general case of $K$ paths.


