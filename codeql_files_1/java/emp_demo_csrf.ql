/**
 * @name Missing CSRF Protection
 * @description Detects potentially state-changing Spring endpoints when CSRF protection is disabled.
 * @kind problem
 * @id java/missing-csrf-protection
 * @problem.severity warning
 * @tags security
 *       external/cwe/cwe-352
 */

import java

/**
 * Checks whether a method is a Spring controller endpoint.
 */
predicate isSpringEndpoint(Method m) {
  exists(Annotation a |
    a = m.getAnAnnotation() and
    (
      a.getType().hasQualifiedName(
        "org.springframework.web.bind.annotation",
        "RequestMapping"
      )
      or
      a.getType().hasQualifiedName(
        "org.springframework.web.bind.annotation",
        "GetMapping"
      )
      or
      a.getType().hasQualifiedName(
        "org.springframework.web.bind.annotation",
        "PostMapping"
      )
      or
      a.getType().hasQualifiedName(
        "org.springframework.web.bind.annotation",
        "PutMapping"
      )
      or
      a.getType().hasQualifiedName(
        "org.springframework.web.bind.annotation",
        "DeleteMapping"
      )
    )
  )
}


/**
 * Checks if endpoint performs state-changing operations.
 */
predicate isStateChanging(Method m) {
  exists(MethodCall call |
    call.getEnclosingCallable() = m and
    (
      call.getMethod().getName().matches("save%")
      or
      call.getMethod().getName().matches("update%")
      or
      call.getMethod().getName().matches("delete%")
      or
      call.getMethod().getName().matches("create%")
    )
  )
}


/**
 * Detects Spring Security csrf().disable()
 *
 * Example:
 * http.csrf().disable();
 */
predicate disablesCsrf(Method m) {
  exists(MethodCall disableCall, MethodCall csrfCall |
    disableCall.getEnclosingCallable() = m
    and
    disableCall.getMethod().getName() = "disable"
    and
    disableCall.getQualifier() = csrfCall
    and
    csrfCall.getMethod().getName() = "csrf"
  )
}


/**
 * Checks if application has disabled CSRF globally.
 */
predicate csrfDisabled() {
  exists(Method m |
    disablesCsrf(m)
  )
}


from Method controller
where
  isSpringEndpoint(controller)
  and
  isStateChanging(controller)
  and
  csrfDisabled()
select
  controller,
  "Potential CSRF vulnerability: state-changing Spring endpoint exists while CSRF protection is disabled."