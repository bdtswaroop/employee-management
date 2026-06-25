/**
 * @name Insecure deserialization sources to ObjectInputStream
 * @description CWE-502: Data from request or uploaded files flows into Java deserialization APIs (ObjectInputStream / ObjectMapper readValue).
 * @id custom/java/insecure-deserialization
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-502
 * @problem.severity error
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module DeserConfig implements DataFlow::ConfigSig {

predicate isSource(DataFlow::Node source) {
  exists(MethodCall mc |
    (mc.getMethod().hasName("getParameter") or mc.getMethod().hasName("getInputStream") or mc.getMethod().hasName("getPart")) and
    source.asExpr() = mc
  )
}

predicate isSink(DataFlow::Node sink) {
  exists(ConstructorCall cons |
    cons.getConstructedType().hasQualifiedName("java.io", "ObjectInputStream") and
    sink.asExpr() = cons.getArgument(0)
  ) or
  exists(MethodCall call |
    call.getMethod().hasName("readValue") and
    call.getMethod().getDeclaringType().getName().regexpMatch("(?i).*ObjectMapper.*") and
    sink.asExpr() = call.getArgument(0)
  )
}

}

module Flow = TaintTracking::Global<DeserConfig>;
import Flow::PathGraph

from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select sink.getNode(), src, sink, "User-controlled data may reach deserialization APIs (ObjectInputStream/ObjectMapper)."
