/** 
 * @name SQL Injection 
 * @description CWE-89: Finds user-controlled data flowing into SQL query execution APIs. 
 * @id custom/java/sql-injection 
 * @tags security 
         external/cwe/cwe-089 
**/

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjectionQuery
import QueryInjectionFlow::PathGraph

from
    QueryInjectionSink query,
    QueryInjectionFlow::PathNode source,
    QueryInjectionFlow::PathNode sink
where
    queryIsTaintedBy(query, source, sink)
    and
    exists(Parameter p |
        p.getAnAnnotation().getType().hasName("RequestParam") and
        source.getNode().asParameter() = p
    )
select
    query,
    source,
    sink,
    "User-controlled @RequestParam reaches SQL query execution."