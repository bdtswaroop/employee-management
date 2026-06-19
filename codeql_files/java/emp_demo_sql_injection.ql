/**

* @name Command Injection through Runtime.exec
* @description Finds user-controlled data flowing into Runtime.exec
* @kind path-problem
* @problem.severity error
* @precision high
* @id custom/java/command-injection-demo
  */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module CommandInjectionConfig implements DataFlow::ConfigSig {

predicate isSource(DataFlow::Node source) {
  exists(Parameter p |
    p.getAnAnnotation().getType().hasName("RequestParam") and
    source.asParameter() = p
  )
}

predicate isSink(DataFlow::Node sink) {
exists(MethodCall call |
   (
      call.getMethod().hasName("createQuery") or
      call.getMethod().hasName("createNativeQuery") or
      call.getMethod().hasName("executeQuery")
    ) and
    sink.asExpr() = call.getArgument(0)
)
}
}

module Flow = TaintTracking::Global<CommandInjectionConfig>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
"User-controlled data reaches Runtime.exec()."