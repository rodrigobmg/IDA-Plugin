# IDA Script



一些我在用的 IDA 插件以及一些我自己写或者收集的IDA 脚本

## plugins

我常用的一些 ida 插件，支持ida 7.4

## script
一些我写的或者收集的脚本
1. **makefunc**     
对所有未 'P' 的函数做 `makefunc`
2. **rename_by_handle**    
根据一些 handle 来重命名函数    
3.  **raname_by_logfunction**      
根据 log 函数来重命名函数

4. **do_oof**

   对一些特殊地址进行 `offset `操作

## idabase

正如我们所知道的， IDAPython 7.4 做了一些大更新，所以我整理了下变化的函数做了

类似于

```python
if idaapi.IDA_SDK_VERSION >= 740:
    from ida_ida import inf_get_max_ea, inf_get_min_ea	    
    from ida_funcs import add_func	    
else:	else:
    from idc import MaxEa as inf_get_max_ea, MinEa as inf_get_min_ea	    
    from idc import MaxEA as inf_get_max_ea, MinEA as inf_get_min_ea
    from idc import MakeFunction as add_func	    

```

这样我们直接用新函数名，进行操作即可

或者：

```python
if idaapi.IDA_SDK_VERSION >= 740:
    from ida_ida import inf_get_max_ea as MaxEa, inf_get_min_ea as MinEa
    from ida_funcs import add_func	as  MakeFunction
else:	else:
    from idc import MaxEa , MinEa 
    from idc import MakeFunction 
```

以旧的API的函数名进行操作
