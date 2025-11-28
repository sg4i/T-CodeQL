/**
* @name Find api
* @description 
* @kind problem
* @problem.severity recommendation
* @id python/example/api
*/

import python
import semmle.python.ApiGraphs

from API::CallNode call
where call = API::moduleImport("aiopg").getMember("connection").getMember("Connection").getAnInstance().getMember("cursor").getReturn().getMember("execute").getACall()
select call, "call api"
