/**
 * @name HTTP Header Injection
 * @description CWE-113: Finds user-controlled data flowing into HTTP response headers.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id custom/java/header-injection-demo
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module HeaderInjectionConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      (
        p.getAnAnnotation().getType().hasName("RequestParam") or
        p.getAnAnnotation().getType().hasName("PathVariable")
      ) and
      source.asParameter() = p
    )
  }

predicate isSink(DataFlow::Node sink) {
  exists(MethodCall call |
    (
    call.getMethod().hasName("header") or
    call.getMethod().hasName("setHeader") or
    call.getMethod().hasName("addHeader")
    ) and
    sink.asExpr() = call.getAnArgument()
  )
}

}

module Flow = TaintTracking::Global<HeaderInjectionConfig>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
"User-controlled data reaches an HTTP response header."