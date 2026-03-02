---
title: "Dynamic Programming and State Transition Equations"
date: 2026-03-02T13:57:00+08:00
description: "An introduction to dynamic programming and state transition equations, with a summary of common problem patterns"
tags:
    - Dynamic Programming
    - State Transition Equation
categories:
    - Algorithm
draft: false
math: true
comments: true
hidden: false
pinned: false
---

The shadow of dynamic programming can be seen in almost any algorithmic problem. This article summarizes dynamic programming (DP) and one of its most important components—the state transition equation.

## I. What is Dynamic Programming?

Dynamic Programming (DP) is an algorithmic approach that solves the original problem by decomposing it into sub-problems.

Dynamic programming is not a specific data structure, but rather a way of thinking.

DP must satisfy the following two properties:

### 1. Optimal Substructure

The optimal solution of the original problem contains the optimal solutions of its sub-problems.

### 2. Overlapping Subproblems

Sub-problems are computed repeatedly and can be cached to avoid duplication.

## II. What is a State Transition Equation?

To understand the state transition equation, you must first know what a "state" is.

### 1. "State"

A state describes the problem at a certain stage, usually denoted by `dp[i]` or `dp[i][j]`.

For example:
- `dp[i]` = optimal solution for the first i elements
- `dp[i][j]` = optimal solution from position i to position j
- `dp[i][w]` = optimal solution considering the first i items with remaining capacity w

### 2. State Transition Equation

The state transition equation can roughly be written as:

```
New State = f(Old State)
```

The state transition equation determines what choices are available at each step and the sub-problems associated with those choices (which can be understood as recursion).

## III. Typical Examples

### 1. Linear DP: Climbing Stairs

**Problem:** You can climb 1 or 2 steps at a time. How many ways can you reach step n?

**Approach Analysis:**

1. Define state: `dp[i]` = number of ways to reach step i
2. Last step analysis: To reach step i, you can only come from step i-1 (climb 1 step) or step i-2 (climb 2 steps)
3. From this analysis, we get the state transition equation:

```
dp[i] = dp[i-1] + dp[i-2]
```

Note: This equation has two boundary states: `dp[1] = 1`, `dp[2] = 2`

4. Illustration:

```
i = 5
dp[1] = 1
dp[2] = 2
dp[3] = 3
dp[4] = 5
dp[5] = 8
```

5. Code Implementation (climbing 5 steps as example):

```c
#include <stdio.h>

int climbStairs(int n) {
    if (n <= 2) return n;
    int dp[n + 1];
    dp[1] = 1;
    dp[2] = 2;
    for (int i = 3; i <= n; i++) {
        dp[i] = dp[i-1] + dp[i-2];  // State transition equation
    }
    return dp[n];
}

int main() {
    printf("Ways to climb 5 steps: %d\n", climbStairs(5));  // Output: 8
    return 0;
}
```

### 2. Linear DP: House Robber

**Problem:** A row of houses can't rob adjacent ones. What's the maximum amount you can steal?

**Approach Analysis:**

1. Define state: `dp[i]` = maximum amount obtainable by robbing up to house i
2. Last step analysis: For house i, either rob it or don't
3. From this analysis, we get the state transition equation:

```
dp[i] = max(dp[i-1], dp[i-2] + nums[i])
```

4. Illustration:

```
nums = [2, 7, 9, 3, 1]
dp[0] = 2
dp[1] = max(2, 7) = 7
dp[2] = max(7, 2+9) = 11
dp[3] = max(11, 7+3) = 11
dp[4] = max(11, 11+1) = 12  (Rob houses 0, 2, 4: 2+9+1=12)
```

5. Code Implementation:

```c
#include <stdio.h>

int max(int a, int b) { return a > b ? a : b; }

int rob(int *nums, int n) {
    if (n == 1) return nums[0];
    int dp[n];
    dp[0] = nums[0];
    dp[1] = max(nums[0], nums[1]);
    for (int i = 2; i < n; i++) {
        dp[i] = max(dp[i-1], dp[i-2] + nums[i]);  // State transition equation
    }
    return dp[n-1];
}

int main() {
    int nums[] = {2, 7, 9, 3, 1};
    int n = sizeof(nums) / sizeof(nums[0]);
    printf("Maximum amount: %d\n", rob(nums, n));  // Output: 12
    return 0;
}
```

### 3. Knapsack DP: 0/1 Knapsack

**Problem:** Given n items with weights `w[]` and values `v[]`, and knapsack capacity W, find the maximum value.

**Approach Analysis:**

1. Define state: `dp[i][j]` = maximum value considering the first i items with capacity j
2. Last step analysis: For item i, either include it or don't
3. From this analysis, we get the state transition equation:

```
Not included: dp[i][j] = dp[i-1][j]
Included:    dp[i][j] = dp[i-1][j - w[i]] + v[i]   (requires j >= w[i])

→ dp[i][j] = max(dp[i-1][j], dp[i-1][j - w[i]] + v[i])
```

4. Illustration:

Items: (w=2, v=3), (w=3, v=4), (w=4, v=5)   Knapsack capacity W=5

```
      j=0  j=1  j=2  j=3  j=4  j=5
i=0    0    0    0    0    0    0
i=1    0    0    3    3    3    3
i=2    0    0    3    4    4    7   ← Include item 1 + item 2, value=3+4=7
i=3    0    0    3    4    5    7

Answer: dp[3][5] = 7
```

5. Code Implementation:

```c
#include <stdio.h>

#define MAX_N 105
#define MAX_W 1005

int dp[MAX_N][MAX_W];

int max(int a, int b) { return a > b ? a : b; }

int knapsack(int *w, int *v, int n, int W) {
    for (int i = 0; i <= n; i++)
        for (int j = 0; j <= W; j++)
            dp[i][j] = 0;

    for (int i = 1; i <= n; i++) {
        for (int j = 0; j <= W; j++) {
            dp[i][j] = dp[i-1][j];                          // Don't include
            if (j >= w[i-1])                                 // Can fit
                dp[i][j] = max(dp[i][j],
                               dp[i-1][j - w[i-1]] + v[i-1]);  // State transition equation
        }
    }
    return dp[n][W];
}

int main() {
    int w[] = {2, 3, 4};
    int v[] = {3, 4, 5};
    int n = 3, W = 5;
    printf("Maximum value: %d\n", knapsack(w, v, n, W));  // Output: 7
    return 0;
}
```

6. Space Optimization

The 2D DP can be compressed to 1D, and the inner loop **must be reversed** to prevent the same item from being used twice:

```c
for (int i = 0; i < n; i++)
    for (int j = W; j >= w[i]; j--)        // Reverse!
        dp[j] = max(dp[j], dp[j - w[i]] + v[i]);
```

### 4. Sequence DP: Longest Common Subsequence (LCS)

**Problem:** Given two strings, find the length of their longest common subsequence. Example: `"abcde"` and `"ace"` → length is 3 (`ace`)

**Approach Analysis:**

1. Define state: `dp[i][j]` = LCS length of first i characters of s1 and first j characters of s2
2. Final step analysis and state transition equation: Whether s1[i] and s2[j] are equal:

```
Equal:     dp[i][j] = dp[i-1][j-1] + 1
Not equal: dp[i][j] = max(dp[i-1][j], dp[i][j-1])
```

3. Illustration:

s1 = "abcde"  s2 = "ace"

```
        ""   a    c    e
    ""   0   0    0    0
    a    0   1    1    1
    b    0   1    1    1
    c    0   1    2    2
    d    0   1    2    2
    e    0   1    2    3   ← Solution found
```

4. Code Implementation:

```c
#include <stdio.h>
#include <string.h>

#define MAX_LEN 105

int dp[MAX_LEN][MAX_LEN];

int max(int a, int b) { return a > b ? a : b; }

int lcs(char *s1, char *s2) {
    int m = strlen(s1);
    int n = strlen(s2);

    for (int i = 0; i <= m; i++) dp[i][0] = 0;
    for (int j = 0; j <= n; j++) dp[0][j] = 0;

    for (int i = 1; i <= m; i++) {
        for (int j = 1; j <= n; j++) {
            if (s1[i-1] == s2[j-1])
                dp[i][j] = dp[i-1][j-1] + 1;           // Characters match
            else
                dp[i][j] = max(dp[i-1][j], dp[i][j-1]); // State transition equation
        }
    }
    return dp[m][n];
}

int main() {
    char s1[] = "abcde";
    char s2[] = "ace";
    printf("LCS length: %d\n", lcs(s1, s2));  // Output: 3
    return 0;
}
```

### 5. Interval DP: Burst Balloons

**Problem:** Bursting balloon i gives score = `nums[i-1] * nums[i] * nums[i+1]`. Find the maximum total score.

**Approach Analysis:**

1. Key insight: Instead of thinking "which balloon to burst first", think "which balloon to burst **last** in interval (i,j)". This way the boundaries on both sides are known, avoiding confusion.
2. Define state: `dp[i][j]` = maximum score for bursting all balloons in open interval (i,j)
3. From this analysis, we get the state transition equation:

```
dp[i][j] = max(dp[i][k] + dp[k][j] + nums[i] * nums[k] * nums[j])
```

where k is the last balloon burst in interval (i,j).

4. Code Implementation:

```c
#include <stdio.h>
#include <string.h>

#define MAX_N 305

int dp[MAX_N][MAX_N];
int nums[MAX_N];

int max(int a, int b) { return a > b ? a : b; }

int maxCoins(int *arr, int n) {
    // Add sentinel boundaries
    nums[0] = 1;
    for (int i = 1; i <= n; i++) nums[i] = arr[i-1];
    nums[n+1] = 1;
    int N = n + 2;

    memset(dp, 0, sizeof(dp));

    // Enumerate by interval length from small to large
    for (int len = 2; len < N; len++) {
        for (int i = 0; i < N - len; i++) {
            int j = i + len;
            for (int k = i+1; k < j; k++) {   // k is the last balloon burst
                int score = dp[i][k] + dp[k][j]
                          + nums[i] * nums[k] * nums[j];
                dp[i][j] = max(dp[i][j], score);  // State transition equation
            }
        }
    }
    return dp[0][N-1];
}

int main() {
    int arr[] = {3, 1, 5, 8};
    int n = sizeof(arr) / sizeof(arr[0]);
    printf("Maximum score: %d\n", maxCoins(arr, n));  // Output: 167
    return 0;
}
```

## IV. Model Summary

| Type | State Transition Equation | Time Complexity |
|------|---------------------------|-----------------|
| Linear DP | `dp[i] = f(dp[i-1], dp[i-2])` | O(n) |
| Knapsack DP | `dp[i][j] = max(don't include, include)` | O(nW) |
| Sequence DP (LCS) | `dp[i][j] = f(dp[i-1][j-1], ...)` | O(mn) |
| Interval DP | `dp[i][j] = max(dp[i][k] + dp[k][j])` | O(n³) |