---
layout: post
title: "Posting Example"
description: Some description here!
headline:
modified: 2016-12-31
categories: research example
imagefeature:
mathjax:
chart:
comments: true
featured: true
---

A couple weeks ago, Microsoft released the [MS16-063][ms16-063]{:target="_blank"} security bulletin for their monthly Patch Tuesday (June 2016) security updates. It addressed vulnerabilities that affected Internet Explorer. Among other things, the patch fixes a memory corruption vulnerability in `jscript9.dll` related to _TypedArray_ and _DataView_.

Second paragraph


### Theme

We begin with comparing the May and June versions of `jscript9.dll` in BinDiff:

<img src="{{ site.url }}/images/2016-12-31/bindiff_diff.png" style="display: block; margin: auto;">

In pseudo-code, it looks like the following:

```cpp
inline Var DirectGetItem(__in uint32 index)
{
    if (index < GetLength())
    {
        TypeName* typedBuffer = (TypeName*)buffer;
        return JavascriptNumber::ToVar(
            typedBuffer[index], GetScriptContext()
        );
    }
    return GetLibrary()->GetUndefined();
}
```

[ms16-063]: https://technet.microsoft.com/en-us/library/security/ms16-063.aspx
