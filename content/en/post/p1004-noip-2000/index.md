---
tags:
    - 算法
categories:
    - 算法
pinned: false
title: "P1004 [NOIP 2000 improvement group] grid score analysis and summary"
description: "date: 2026-02-28T11:31:04+08:00"
date: 2026-02-28T11:31:00+08:00
image: ""
math: false
license: ""
hidden: false
comments: true
draft: false
ws_sync_zh_hash: "08d9623d5630b95a61578204e9753730521faf5f04db3fd269617cb91c2a00a2"
---This is a classic but difficult chessboard model problem. Although it is a NOIP problem in 2000, it is still quite difficult for first-time contacts like me as the finale.

Look at the background of the question first

NOIP 2000 improvement group T4

Question description
There is a square diagram of N × N (N ≤ 9), some of which we fill in positive integers, while others put the number 0.

Someone starts at point A (0, 0) in the top left corner of the diagram and can walk down or to the right until they reach point B (N, N) in the bottom right corner. On the way he walks, he can take the number in the square (which becomes the number 0).

This person walked from point A to point B twice, trying to find 2 such paths, so that the sum of the obtained numbers is the maximum.

Input format
The first line of the input is an integer N (representing the grid diagram of N × N), the next row has three integers, the first two represent the position, and the third number is the number put on the position.A separate line of 0 indicates the end of the input.

Output format
Just output an integer representing the maximum sum obtained on the 2 paths.

Sample input/output
Input
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

Output
67

Instructions/Tips
Data range: 1 ≤ N ≤ 9.

I initially tried to enumerate the matrix that had been changed (that is, simulated) again after a round of enumeration, but found that the difficulty was a little too great. Finally, I couldn't think of a solution, so I found Claude's teacher. The solution it gave was to use the dp algorithm (see method 1 for details). I thought of the algorithm of DFS combined with pruning (thank you for the maze problem I did before, it is an algorithm problem related to the minimum number of steps, which is just suitable for DFS combined with pruning) (see method 2 for details). Later, Claude also gave an algorithm that is suitable for general solutions - the cost flow solution method (too difficult, belonging to the hyper-schema solution method, sketching one or two, see method 3 for details).

ps. Explain why two enums cannot be taken. One path changes the map, affecting the second, so the two paths must be considered in conjunction.

Solution 1 (dp dynamic programming):

Core idea: Advance both paths simultaneously and simulate two people walking at the same time with one DP.

State design: set dp [k] [x1] [x2], where:

k is the number of steps currently taken (i.e. the value of x + y, from 2 to 2N)
x1 and x2 are the line numbers where the two people are currently located.
By k and x can be derived y = k - x (key, this step reduces the dimension), so the column number does not need to be stored separately

Deduplication: When two people are in the same cell (x1 = = x2, then y1 = = y2), the cell is taken only once.

Transfer: Two people each can choose to move to the right or down for a total of 4 combinations.

Full code __ code_block_0 __\ n\ n

Time complexity: O (N ³)

Solution 2 (DFS + pruning):

Core idea: Similar to the dp algorithm (after all, deep search and dp are essentially one thing), but adds the step of memorized search, avoiding repetitive searches. (If there is no memory search, the amount of calculation will be an exponential explosion, about 4 ^ 16 times at N = 9)

Full code __ code_block_1 __\ n\ n

Time complexity: O (N ³)

Solution 3 (Cost Flow Solution):

Core idea: Convert "maximizing the two paths" into a network flow problem.

Modeling Ideas
Key Observations:
Two paths from A to B = 2 flows from source to sink
Fetch at most once per cell = 1 capacity per node
Get number max = cost max (min to min)

Split point: Each grid (i, j) is split into two nodes in and out:
in → out: Capacity 1, Cost -map [i] [j] (minimize costs by minimizing costs)
in → out: add one more capacity 1, cost 0 (allow the second path to go through but do not take repeated values)
Namely: Consolidated to Capacity 2, but only the first unit stream has revenue

Connected edges: (i, j) out connects (i +1, j) in and (i, j +1) in, capacity 2, cost 0.

Source sink: The source point S is connected to (1,1) .in, (N, N) .out is connected to the sink point T, and the traffic is 2.

After splitting each grid (i, j):

Capacity 1, cost-val (first way through, take the number)
in (i, j) = = = = = = = = = = = = = = = = > out (i, j)
        Capacity 1, cost 0 (second way through, number taken)

Full code (MCMF, SPFA implementation) __ code_block_2 __\ n\ n

Time complexity: O (E · SPFA)

Advantage: Easily scales to K paths.


