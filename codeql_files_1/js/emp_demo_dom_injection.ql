/**
 * @name DOM XSS through innerHTML
 * @description CWE-79: Improper neutralization of input during web page generation (Cross-site Scripting).
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-079
 * @problem.severity error
 * @precision high
 * @id custom/javascript/dom-xss-innerhtml
 */

import javascript
import semmle.javascript.security.dataflow.XssThroughDomQuery
import XssThroughDomFlow::PathGraph

from
    XssThroughDomFlow::PathNode source,
    XssThroughDomFlow::PathNode sink
where
    XssThroughDomFlow::flowPath(source, sink)
    and
    exists(CallExpr jsonCall |
        jsonCall.getCalleeName() = "json" and
        source.getNode().asExpr() = jsonCall
    )
select
    sink.getNode(),
    source,
    sink,
    "User-controlled data reaches a DOM XSS sink."