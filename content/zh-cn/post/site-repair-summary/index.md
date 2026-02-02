---
title: "网站修复总结"
description: 
date: 2026-02-02T12:14:36+08:00
image: 
math: 
license: 
hidden: false
comments: true
draft: true
---

之前用力过猛，GitHub Copilot 额度用完了，停了一段时间，中途还霍霍了Antigravity，Trae 和 CodeBuddy，不过收效甚微，今天终于大概修复好了网站大大小小的一堆问题。

首先是左下栏动画卡顿，一开始一直以为是动画的问题，添加了贝塞尔曲线还是没有用，最后发现是高度没有固定，导致出现跳动……然后是中英文界面的切换问题，为了图省事，我做了中英文的两个环境，保证在点击“Home”的时候不会跳转到“首页”去。还处理了头像消失和计数功能的问题，把Umami的API调用给处理好了。

目前正在完善WSwriter的预览和提交功能，便于一键编辑和提交文章。