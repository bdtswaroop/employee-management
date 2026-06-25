/**
 * @name Command injection via Runtime.exec / ProcessBuilder
 * @description CWE-78: User-controlled input flows to OS command execution APIs.
 * @id custom/java/command-injection
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-078
 * @problem.severity error
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module CmdConfig implements DataFlow::ConfigSig {

predicate isSource(DataFlow::Node source) {
  exists(Parameter p |
    source.asParameter() = p and
    exists(Annotation a |
      a = p.getAnAnnotation() and a.getType().hasName("RequestParam")
    )
  )
  or
  exists(MethodCall mc | mc.getMethod().hasName("getParameter") and source.asExpr() = mc)
}

predicate isSink(DataFlow::Node sink) {
  exists(MethodCall call |
    (
      call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      call.getMethod().hasName("exec")
    ) and
    sink.asExpr() = call.getArgument(0)
  ) or
  exists(ConstructorCall cons |
    cons.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder") and
    sink.asExpr() = cons.getArgument(0)
  )
}

}

module Flow = TaintTracking::Global<CmdConfig>;
import Flow::PathGraph

from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select sink.getNode(), src, sink, "User-controlled data reaches OS command APIs (Runtime.exec / ProcessBuilder)."
