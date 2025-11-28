/**
* @name Find execute functions
* @description Find all Python functions named 'execute'
* @kind problem
* @problem.severity recommendation
* @id python/example/execute-functions
*/

import python

from Function f
where f.getName() = "execute"
select f, "This function is named 'execute'."
