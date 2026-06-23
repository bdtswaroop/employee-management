/**
 * @name SQL Injection
 * @description CWE-89: User-controlled data flows into SQL query execution APIs.
 * @id custom/java/sql-injection
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-089
 * @problem.severity error
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module SQLInjectionConfig implements DataFlow::ConfigSig {

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

module Flow = TaintTracking::Global<SQLInjectionConfig>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
"User-controlled data reaches SQL query execution API."



//The below is a more complete version of the above query, which also includes support for PathVariable and PathParam, as well as additional sinks such as executeUpdate and execute.

// import java
// import semmle.code.java.dataflow.DataFlow
// import semmle.code.java.dataflow.TaintTracking

// module SqlInjectionConfig implements DataFlow::ConfigSig {

//   predicate isSource(DataFlow::Node source) {
//     exists(Parameter p |
//       (
//         p.getAnAnnotation().getType().hasName("RequestParam") or
//         p.getAnAnnotation().getType().hasName("PathVariable") or
//         p.getAnAnnotation().getType().hasName("PathParam")
//       ) and
//       source.asParameter() = p
//     )
//     or
//     exists(MethodCall mc |
//       mc.getMethod().hasName("getParameter") and
//       source.asExpr() = mc
//     )
//   }

//   predicate isSink(DataFlow::Node sink) {
//     exists(MethodCall call |
//       (
//         (
//           call.getMethod().hasName("createQuery") and
//           call.getMethod().getDeclaringType().hasQualifiedName(
//             "jakarta.persistence", "EntityManager"
//           )
//         )
//         or
//         (
//           call.getMethod().hasName("createNativeQuery") and
//           call.getMethod().getDeclaringType().hasQualifiedName(
//             "jakarta.persistence", "EntityManager"
//           )
//         )
//         or
//         (
//           call.getMethod().hasName("executeQuery") and
//           call.getMethod().getDeclaringType().hasQualifiedName(
//             "java.sql", "Statement"
//           )
//         )
//         or
//         (
//           call.getMethod().hasName("executeUpdate") and
//           call.getMethod().getDeclaringType().hasQualifiedName(
//             "java.sql", "Statement"
//           )
//         )
//         or
//         (
//           call.getMethod().hasName("execute") and
//           call.getMethod().getDeclaringType().hasQualifiedName(
//             "java.sql", "Statement"
//           )
//         )
//       ) and
//       sink.asExpr() = call.getArgument(0)
//     )
//   }
// }

// module Flow = TaintTracking::Global<SqlInjectionConfig>;

// import Flow::PathGraph

// from Flow::PathNode source, Flow::PathNode sink
// where Flow::flowPath(source, sink)
// select
//   sink.getNode(),
//   source,
//   sink,
//   "User-controlled data reaches a SQL query execution API."