/**
 * @name CWE-94 DOM Injection with barriers
 * @kind path-problem
 */

import javascript
import semmle.javascript.dataflow.TaintTracking

module Config implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    exists(CallExpr call |
      call.getCalleeName() = "fetch" and
      source.asExpr() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(AssignExpr assign |
      assign.getLhs().toString().regexpMatch(".*innerHTML.*") and
      sink.asExpr() = assign.getRhs()
    )
  }

   predicate isBarrier(DataFlow::Node node) {
    exists(CallExpr call |
      (
        call.getCalleeName() = "renderFileLink"
        or
        call.getCalleeName() = "field"
      )
      and
      node.asExpr() = call
    )
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink, source, sink,
  "Potential DOM XSS (CWE-94) with barrier filtering."