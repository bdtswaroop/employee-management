/**
 * @name External Control of File Name or Path
 * @description CWE-73: User-controlled filename flows into file path operations.
 * @id custom/java/path-control
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-073
 * @problem.severity error
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module PathControlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(MethodCall call |
      call.getMethod().hasName("getOriginalFilename") and
      call.getMethod().getDeclaringType().hasQualifiedName("org.springframework.web.multipart","MultipartFile") and
      source.asExpr() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().hasName("resolve") and
      call.getMethod().getDeclaringType().hasQualifiedName("java.nio.file","Path") and
      sink.asExpr() = call.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(MethodCall call |
      call.getMethod().hasName("replaceAll") and
      node.asExpr() = call
    )
  }
}

module Flow = TaintTracking::Global<PathControlConfig>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
"User-controlled filename flows into file path resolution without sanitization."
