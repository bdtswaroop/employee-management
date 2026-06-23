/**
 * @name Client-side Open Redirect
 * @kind path-problem
 * @id custom/js/open-redirect
 * @problem.severity error
 * @Description CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
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
      assign.getLhs().toString().regexpMatch(".*location\\.href.*") and
      sink.asExpr() = assign.getRhs()
    )
  }

predicate isBarrier(DataFlow::Node node) {
  exists(CallExpr call |
    call.getCalleeName().matches(
      "isAllowedRedirect|isSafeRedirect|validateRedirectUrl|isTrustedRedirect|validate"
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
  "User controlled data reaches redirect target."