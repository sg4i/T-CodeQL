/**
* @name Find execute call
* @description Find all Python calls to the 'execute' function
* @kind problem
* @problem.severity recommendation
* @id python/example/call
*/

import python

// from Call call, Name name
// where name.getId() = "get_session" and call.getFunc() = name 
// select call, "execute call at location: " + call.getLocation().toString() + " in module: " + call.getEnclosingModule().getName()

// 谓词（如过滤条件或连接操作）的顺序会影响查询引擎的执行计划。
// 查询引擎通常从左到右或根据内部优化器处理谓词，
// 因此应优先放置选择性强（能快速过滤掉大部分数据）的谓词
// 高选择性的谓词（如 equality 检查或简单属性过滤）应置于前面，以减少后续操作的输入规模



from Call call
where exists(Name name | name.getId() = "get_session" and call.getFunc() = name) 
select call, "execute call at location: " + call.getLocation().toString() + " in module: " + call.getEnclosingModule().getName()
