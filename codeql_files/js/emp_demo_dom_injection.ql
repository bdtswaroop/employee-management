/**
* @name DOM XSS through innerHTML
* @description CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
* @kind path-problem
* @problem.severity error
* @precision high
* @id custom/javascript/dom-xss-innerhtml
**/

import javascript
import semmle.javascript.dataflow.TaintTracking


module Config implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {

    exists(CallExpr jsonCall |
      jsonCall.getCalleeName() = "json" and
      source.asExpr() = jsonCall
    )
  }

  predicate isSink(DataFlow::Node sink) {

    exists(AssignExpr assign |
      assign.getLhs().toString().regexpMatch(".*innerHTML.*")
      and
      sink.asExpr() = assign.getRhs()
    )
  }

  predicate isBarrier(DataFlow::Node node) {

    exists(CallExpr call |
      call.getCalleeName() = "encodeURIComponent"
      and
      node.asExpr() = call
    )
  }
}


module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph
from
    Flow::PathNode source,
    Flow::PathNode sink

where
    Flow::flowPath(source,sink)

select
    sink,
    source,
    sink,
    "User controlled data reaches innerHTML and may create href injection."



//Updated version of the above query to include barriers. Keeping the above query for reference and comparison.
// import javascript
// import semmle.javascript.dataflow.TaintTracking

// module Config implements DataFlow::ConfigSig {

//   predicate isSource(DataFlow::Node source) {
//     exists(CallExpr call |
//       call.getCalleeName() = "fetch" and
//       source.asExpr() = call
//     )
//   }

//   predicate isSink(DataFlow::Node sink) {
//     exists(AssignExpr assign |
//       assign.getLhs().toString().regexpMatch(".*innerHTML.*") and
//       sink.asExpr() = assign.getRhs()
//     )
//   }

//    predicate isBarrier(DataFlow::Node node) {
//     exists(CallExpr call |
//       (
//         call.getCalleeName() = "renderFileLink"
//         or
//         call.getCalleeName() = "field"
//       )
//       and
//       node.asExpr() = call
//     )
//   }
// }

// module Flow = TaintTracking::Global<Config>;

// import Flow::PathGraph

// from Flow::PathNode source, Flow::PathNode sink
// where Flow::flowPath(source, sink)
// select sink, source, sink,
//   "Potential DOM XSS (CWE-94) with barrier filtering."