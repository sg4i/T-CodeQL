/**
* @name Find attribute
* @description 
* @kind problem
* @problem.severity recommendation
* @id python/example/attribute
*/

import python

from Attribute attr
where attr.getName() = "execute"
select attr.getObject(), "attr execute function"
