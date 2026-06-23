/**
 * @name Path Traversal Flow
 * @description CWE-22: User-controlled data flows into file system operations.
 * @id custom/java/path-traversal
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-022
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module Config implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
  exists(Parameter p |
    source.asParameter() = p and
    exists(Annotation a |
      a = p.getAnAnnotation() and
      a.getType().hasQualifiedName(
        "org.springframework.web.bind.annotation",
        "PathVariable"
      )
      // or
      //  a.getType().hasQualifiedName(
      //   "org.springframework.web.bind.annotation",
      //   "RequestParam"
      // )
    )
  )
}

predicate isSink(DataFlow::Node sink) {
  exists(ConstructorCall call |
    call.getConstructedType().hasQualifiedName(
      "org.springframework.core.io",
      "UrlResource"
    ) and
    sink.asExpr() = call.getArgument(0)
  )
}


predicate isBarrier(DataFlow::Node node) {
  exists(MethodCall call, Method m |
    node.asExpr() = call and
    m = call.getMethod() and
    exists(MethodCall sw |
      sw.getMethod().hasName("startsWith") and
      sw.getEnclosingCallable() = m
    )
    // or
    // exists(MethodCall sw |
    //   sw.getMethod().hasName("contains") or
    //   sw.getEnclosingCallable() = m
    // )
  )
}
}

predicate isPathConstruct(MethodCall call) {
  call.getMethod().getDeclaringType().hasQualifiedName(
    "java.nio.file", "Paths"
  ) and
  call.getMethod().hasName("get")
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select sink, src, sink,
  "User controlled path reaches file operation."