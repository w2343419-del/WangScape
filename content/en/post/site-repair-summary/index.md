---
title: "Site Repair Summary"
description: 
date: 2026-02-02T12:14:36+08:00
image: 
math: 
license: 
hidden: false
comments: true
draft: true
---

Previously too hard, GitHub Copilot ran out of credits, stopped for a while, and halfway through Antigravity, Trae, and CodeBuddy, but with little success, today finally fixed a bunch of problems with the size of the website.

First of all, the animation carton in the lower left column. At first, I always thought that it was a problem of animation. It was still useless to add the Bezier curve. Finally, it was found that the height was not fixed, resulting in a jump... Then there was the problem of switching between the Chinese and English interfaces. In order to save trouble, I made two environments in Chinese and English to ensure that I would not jump to the "home page" when clicking "Home". It also handled the issue of avatar disappearance and counting function, and handled Umami's API call.

WSwriter's preview and submission capabilities are currently being refined to facilitate one-click editing and submission of articles.