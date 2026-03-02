---
tags:
    - Algorithm
categories:
    - Algorithm
pinned: false
title: "P1004 [NOIP 2000 Improvement Group] Grid Number Collection - Analysis and Summary"
description: "Multiple solution approaches for the classic grid path problem: Dynamic Programming, DFS with Memoization, and Minimum Cost Maximum Flow"
date: 2026-02-28T11:31:00+08:00
image: ""
math: false
license: ""
hidden: false
comments: true
draft: false
---

This is a classic but challenging grid path problem. Although it is a NOIP 2000 final problem, it remains quite difficult for those encountering it for the first time. This article summarizes three different approaches: Dynamic Programming, DFS with Memoization, and Minimum Cost Maximum Flow, progressing gradually from easy to difficult.

## Problem Background and Description

NOIP 2000 Improvement Group T4

### Problem Statement

There is an N×N grid (N≤9) in which some cells contain positive integers, while others contain 0.
A person starts at point A (0, 0) in the top-left corner and can move either down or right until reaching point B (N, N) in the bottom-right corner. Along the way, they can collect the number in each cell (which then becomes 0).
This person travels from A to B twice. Find 2 such paths so that the sum of collected numbers is maximized.

### Input Format

The first line is an integer N (representing the N×N grid). Each subsequent line contains three integers: the first two represent a position, and the third is the number placed at that position. A line containing only 0 indicates the end of input.

### Output Format

Output a single integer representing the maximum sum obtainable from the 2 paths.

### Sample Input/Output

**Input:**
```
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

**Output:**
```
67
```

### Constraints

Data range: 1≤N≤9.

---

## Solution Approach

Initially, I attempted to enumerate one path and then enumerate again with the modified grid (simulating number collection). However, this approach proved overly complex. Eventually, I consulted Claude, which provided a DP solution (detailed below). I also came up with a DFS with pruning approach (inspired by a similar maze problem from earlier). Later, Claude suggested a more general solution using cost flow (highly advanced, beyond typical scope; outlined briefly below).

**Note:** Why can't we use two separate enumerations? Because one path modifies the grid, affecting the second path. The two paths must be considered together.

---

## Solution 1: Dynamic Programming

**Core Idea:** Advance both paths simultaneously and use a single DP to simulate two people walking at the same time.

**State Design:** Let dp[k][x1][x2], where:
- k = current number of steps taken (i.e., x + y, ranging from 2 to 2N)
- x1, x2 = row numbers of the two people

From k and x, we can derive y = k - x (key insight that reduces dimensions), so column numbers don't need separate storage.

**Deduplication:** When both people occupy the same cell (x1 == x2, thus y1 == y2), that cell is only collected once.

**Transitions:** Each person can choose to move right or down, giving 4 combinations total.

**Time Complexity:** O(N³)

**Complete Code:**
```c
#include <stdio.h>

int N;
int map[10][10];
int dp[20][10][10]; // dp[steps][person1_row][person2_row]

int main() {
    scanf("%d", &N);

    int x, y, v;
    while (scanf("%d %d %d", &x, &y, &v) && (x || y || v))
        map[x][y] = v;

    // Initialize with -1 to mark unreachable states
    for (int k = 0; k < 20; k++)
        for (int i = 0; i < 10; i++)
            for (int j = 0; j < 10; j++)
                dp[k][i][j] = -1;

    dp[2][1][1] = map[1][1];

    // ========== DP Main Loop ==========
    for (int k = 2; k < 2 * N; k++) {
        for (int x1 = 1; x1 <= N; x1++) {
            int y1 = k - x1;
            if (y1 < 1 || y1 > N) continue;

            for (int x2 = x1; x2 <= N; x2++) {
                int y2 = k - x2;
                if (y2 < 1 || y2 > N) continue;
                if (dp[k][x1][x2] < 0) continue;

                // Try all 4 movement combinations
                for (int m1 = 0; m1 <= 1; m1++) {
                    for (int m2 = 0; m2 <= 1; m2++) {
                        int nx1 = x1 + m1,     ny1 = y1 + (1 - m1);
                        int nx2 = x2 + m2,     ny2 = y2 + (1 - m2);

                        if (nx1 > N || ny1 > N) continue;
                        if (nx2 > N || ny2 > N) continue;

                        // Calculate gain from current step
                        int gain = map[nx1][ny1];
                        if (nx1 != nx2) gain += map[nx2][ny2];

                        // Normalize: ensure a <= b
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

---

## Solution 2: DFS with Memoization

**Core Idea:** Similar to DP (DFS and DP are essentially equivalent), but with memoized search to avoid redundant computations. Without memoization, the computation would explode exponentially—approximately 4^16 operations for N=9.

**Time Complexity:** O(N³)

**Complete Code:**
```c
#include <stdio.h>
#include <string.h>

// ========== DFS with Memoization ==========

int N;
int map[10][10];
int memo[20][10][10];    // Memoization array
int visited[20][10][10]; // Visited flag

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

---

## Solution 3: Minimum Cost Maximum Flow

**Core Idea:** Transform "two paths collecting maximum value" into a network flow problem.

### Modeling Approach

**Key Observation:**
- Two paths from A to B = flow of 2 from source to sink
- Each cell collectible at most once = node capacity of 1
- Maximize collected value = minimize negative cost flow

**Node Splitting:** Each cell (i,j) is split into two nodes in and out:
- in → out: capacity 1, cost -map[i][j] (negative because we minimize)
- in → out: additional capacity 1, cost 0 (second path passes without collecting)
- Combined: capacity 2, but only first unit has profit

**Edge Construction:** out node of (i,j) connects to in nodes of (i+1,j) and (i,j+1), both with capacity 2 and cost 0.

**Source and Sink:** Source S connects to (1,1)_in, (N,N)_out connects to sink T, both with flow 2.

**Complete Code (MCMF with SPFA):**
```c
#include <stdio.h>
#include <string.h>

#define MAXN 1000
#define MAXE 10000
#define INF  0x3f3f3f3f

// ========== Adjacency List Data Structure ==========

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

// ========== SPFA Algorithm ==========

int spfa(int s, int t, int n) {
    memset(dist, 0x3f, sizeof(int) * (n + 1));
    memset(in_queue, 0, sizeof(int) * (n + 1));
    dist[s] = 0;

    int front = 0, rear = 0;
    queue[rear++] = s;
    in_queue[s] = 1;

    // SPFA Main Loop
    while (front != rear) {
        int u = queue[front++];
        in_queue[u] = 0;

        // Relaxation
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

// ========== MCMF ==========

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

**Advantage:** Easily extensible to K paths.


