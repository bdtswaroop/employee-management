/**
 * @name HTTP Header Injection
 * @description CWE-113: User-controlled data flows into HTTP response headers.
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-113
 * @problem.severity error
 * @precision high
 * @id custom/java/header-injection-demo
 */

 
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

import custom.sources


module HeaderInjectionConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    Sources::isUserControlledExpr(source)
  }


  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      (
        call.getMethod().hasName("header") or
        call.getMethod().hasName("setHeader") or
        call.getMethod().hasName("addHeader")
      )
      and
      sink.asExpr() = call.getAnArgument()
    )
  }

}


module Flow = TaintTracking::Global<HeaderInjectionConfig>;

import Flow::PathGraph

from
    Flow::PathNode source,
    Flow::PathNode sink
where
    Flow::flowPath(source, sink)
select
    sink.getNode(),
    source,
    sink,
    "User-controlled data reaches an HTTP response header."