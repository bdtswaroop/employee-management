/**
 * @name Common Java User Input Sinks
 * @description Shared sinks definitions for security queries.
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module Sinks {

  predicate isObjectInputStreamSink(DataFlow::Node sink) {
    exists(ConstructorCall cons |
      cons.getConstructedType().hasQualifiedName(
        "java.io",
        "ObjectInputStream"
      )
      and
      sink.asExpr() = cons.getArgument(0)
    )
  }


  predicate isObjectMapperSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().getName() = "readValue"
      and
      call.getMethod().getDeclaringType().hasQualifiedName(
        "com.fasterxml.jackson.databind",
        "ObjectMapper"
      )
      and
      sink.asExpr() = call.getArgument(0)
    )
  }
  
  /**
   * Insecure Deserialization sinks
   */
  predicate isDeserializationSink(DataFlow::Node sink) {
    isObjectInputStreamSink(sink)
    or
    isObjectMapperSink(sink)
  }

}