/**
 * @name Employee User Input in Exception Message
 * @description CWE-209: Finds request-controlled values used in exception messages.
 * @id custom/java/emp-demo-error-message-user-input
 * @kind path-problem
 * @problem.severity error
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module ErrorMessageConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      source.asParameter() = p and
      (
        p.getAnAnnotation().getType().hasQualifiedName(
          "org.springframework.web.bind.annotation", "RequestParam"
        ) or
        p.getAnAnnotation().getType().hasQualifiedName(
          "org.springframework.web.bind.annotation", "PathVariable"
        )
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(ConstructorCall call |
      call.getConstructedType().hasQualifiedName("java.lang", "IllegalArgumentException") and
      call.getNumArgument() > 0 and
      sink.asExpr() = call.getArgument(0)
    )
  }
}

module Flow = TaintTracking::Global<ErrorMessageConfig>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Request-controlled value reaches an exception message."
