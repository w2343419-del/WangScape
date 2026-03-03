---
title: "State Transition Equation, with Dynamic Programming"
date: 2026-03-02T13:57:00+08:00
description: "Summary of dynamic programming and state transition equations, with common models"
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
ws_sync_zh_hash: "ef4560380d923d4d852d25dc5e1187587daa73b37c1b1e120d52828ff6954cda"
---

In algorithmic problems, we can often see the shadow of dynamic programming, so here is a summary of dynamic programming (DP) and a very important part of it - the state transition equation.

## 1. What is Dynamic Programming

Dynamic Programming (DP) is an algorithmic idea that solves the original problem by decomposing it into sub-problems.

Dynamic planning is not some specific data structure, but a way of thinking.

DP needs to meet the following two properties:

### 1. Optimal Substructure

The optimal solution of the original problem contains the optimal solution of the subproblem.

### 2. Overlapping Subproblems

Subquestions are computed iteratively and can be cached to avoid duplication.

## 2. What is State Transition Equation

To understand the state transition equation, you should first know what a "state" is.

### 1. "State"

Status is a description of the problem at a certain stage, usually denoted by `dp [i]` or `dp [i] [j]`.

For example:
- `dp [i]` = optimal solution for the first i elements
- `dp [i] [j]` = optimal solution from position i to position j
- `dp [i] [w]` = optimal solution considering the first i items with remaining capacity w

### 2. State Transition Equation

The state transition equation can be roughly written as:

__ code_block_0 __

What the state transition equation does is determine what options are available for that step, as well as the sub-problems behind the choices (which can be understood as recursive).

## 3. Typical Examples

### 1. Linear DP: Climbing Stairs

* * Question: * * How many ways can you climb 1 or 2 steps at a time to reach step n?

* * Idea Analysis: * *

1. Define status: `dp [i]` = Number of methods to climb to level i
2. Last step analysis: to reach step i, you can only come from step i-1 (step 1) or step i-2 (step 2)
3. Based on the analysis, we can obtain such a state transition equation:

__ code_block_1 __

Note: There are two more boundary states in this state transition equation: `dp [1] = 1`, `dp [2] = 2`

4. Illustration:

__ code_block_2 __

5. Code implementation (take climbing 5 layers as an example):

__ code_block_3 __

### 2. Linear DP: House Robber

* * Problem: * * A row of houses can't rob neighbors, ask for the maximum amount.

* * Idea Analysis: * *

1. Define status: `dp [i]` = the maximum amount you can get for grabbing room i
2. Last step analysis: room i, either rob or not rob
3. Based on the analysis, we can obtain such a state transition equation:

__ code_block_4 __

4. Illustration:

__ code_block_5 __

5. Code Implementation:

__ code_block_6 __

### 3. Knapsack DP: 0/1 Knapsack

* * Question: * * n items, weight `w []`, value `v []`, back capacity W, for maximum value.

* * Idea Analysis: * *

1. Define status: `dp [i] [j]` = maximum value considering the first i items, capacity j
2. Last step analysis: the ith item, put or not put
3. Based on the analysis, we can obtain such a state transition equation:

__ code_block_7 __

4. Illustration:

Items: (w = 2, v = 3), (w = 3, v = 4), (w = 4, v = 5) Back carrying capacity W = 5

__ code_block_8 __

5. Code Implementation:

__ code_block_9 __

6. Space Optimization

The two-dimensional dp can be compressed in one dimension, and the inner loop * * must be reversed * * to prevent the same item from being repeatedly placed:

__ code_block_10 __

### 4. Sequence DP: Longest Common Subsequence (LCS)

* * Problem: * * Two strings to find the length of the longest common subsequence. Example: `"abcde"` and `"ace"` → length is 3 (`ace`)

* * Idea Analysis: * *

1. Define the status: `dp [i] [j]` = LCS length of the first i characters of s1 and the first j characters of s2
2. Final step analysis and state transition equation judgment: whether s1 [i] and s2 [j] are equal:

__ code_block_11 __

3. Illustration:

s1 = "abcde" s2 = "ace"

__ code_block_12 __

4. Code Implementation:

__ code_block_13 __

### 5. Interval DP: Burst Balloons

* * Question: * * Poke balloon i score = `nums [i-1] * nums [i] * nums [i +1]` for maximum total score.

* * Idea Analysis: * *

1. Key idea: Do not want to "poke which first", but "poke which * * last * * in the interval (i, j)", so that the boundaries on both sides are known to avoid confusion
2. Define status: `dp [i] [j]` = Maximum score for all balloons in punctured open interval (i, j)
3. Based on the analysis, we can obtain such a state transition equation:

__ code_block_14 __

where k is the last poked balloon in interval (i, j).

4. Code Implementation:

__ code_block_15 __

## 4. Model Summary

__ code_block_16 __