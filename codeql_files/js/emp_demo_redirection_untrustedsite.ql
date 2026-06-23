/**
 * @name Client-side Open Redirect
 * @description CWE-601: URL Redirection to Untrusted Site (Open Redirect)
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-601
 * @problem.severity error
 * @id custom/js/open-redirect
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