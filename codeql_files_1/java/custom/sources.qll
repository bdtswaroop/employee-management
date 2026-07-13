/**
 * @name Common Java User Input Sources
 * @description Shared source definitions for security queries.
 */

import java
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module Sources {

  /**
   * Spring @RequestParam
   */
  predicate isRequestParam(Parameter p) {
    p.getAnAnnotation().getType().hasQualifiedName(
      "org.springframework.web.bind.annotation",
      "RequestParam"
    )
  }


  /**
   * Spring @PathVariable
   */
  predicate isPathVariable(Parameter p) {
    p.getAnAnnotation().getType().hasQualifiedName(
      "org.springframework.web.bind.annotation",
      "PathVariable"
    )
  }

   /**
   * Spring @RequestHeader
   */
  predicate isRequestHeader(Parameter p) {
    p.getAnAnnotation().getType().hasQualifiedName(
      "org.springframework.web.bind.annotation",
      "RequestHeader"
    )
  }


  /**
   * Any Spring user-controlled parameter
   */
  predicate isSpringUserInput(Parameter p) {
    isRequestParam(p)
    or
    isPathVariable(p)
    or
    isRequestHeader(p)
  }

  /**
   * Servlet request parameters
   */
  predicate isServletInput(MethodCall call) {
    call.getMethod().getDeclaringType().hasQualifiedName(
      "javax.servlet.http",
      "HttpServletRequest"
    )
    and
    (
      call.getMethod().hasName("getParameter")
      or
      call.getMethod().hasName("getParameterValues")
      or
      call.getMethod().hasName("getHeader")
      or
      call.getMethod().hasName("getInputStream")
      or
      call.getMethod().hasName("getReader")
      or
      call.getMethod().hasName("getPart")
    )
  }

  /**
   * Generic user-controlled source expression.
   */
  predicate isUserControlledExpr(DataFlow::Node source) {
    exists(Parameter p |
      isSpringUserInput(p)
      and
      source.asParameter() = p
    )
    or
    exists(MethodCall call |
      isServletInput(call)
      and
      source.asExpr() = call
    )
  }

}