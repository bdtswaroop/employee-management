/**
 * @name document.write / document.writeln with untrusted data
 * @description Detect flows from user-controllable sources into document.write / writeln.
 * @kind path-problem
 * @id custom/javascript/document-write-xss
 * @tags security
 *       external/cwe/cwe-079
 * @problem.severity error
 */

import javascript
import semmle.javascript.dataflow.TaintTracking

module Config implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {

    exists(PropAccess p |
      p.getPropertyName() = "search" and
      source.asExpr() = p
    )

    or

    exists(PropAccess p |
      p.getPropertyName() = "cookie" and
      source.asExpr() = p
    )

    or

    exists(CallExpr c |
      c.getCalleeName() = "fetch" and
      source.asExpr() = c
    )

    or

    exists(CallExpr c |
      c.getCallee().toString().regexpMatch(".*getElementById.*") and
      source.asExpr() = c
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CallExpr c |
      (
        c.getCallee().toString() = "document.write" or
        c.getCallee().toString() = "document.writeln"
      ) and
      sink.asExpr() = c.getArgument(0)
    )
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select
  sink.getNode(),
  src,
  sink,
  "User-controlled data flows into document.write/writeln."