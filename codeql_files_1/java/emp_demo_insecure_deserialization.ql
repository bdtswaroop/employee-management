/**
 * @name Insecure deserialization sources to ObjectInputStream
 * @description CWE-502: User-controlled data reaches Java deserialization APIs.
 * @id custom/java/insecure-deserialization
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-502
 * @problem.severity error
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import Flow::PathGraph

import custom.sources
import custom.sinks


module DeserializationConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    Sources::isUserControlledExpr(source)
  }

  predicate isSink(DataFlow::Node sink) {
    Sinks::isDeserializationSink(sink)
  }
}


module Flow = TaintTracking::Global<DeserializationConfig>;

from
    Flow::PathNode source,
    Flow::PathNode sink
where
    Flow::flowPath(source, sink)
select
    sink.getNode(),
    source,
    sink,
    "User-controlled data may reach deserialization APIs (ObjectInputStream/ObjectMapper)."