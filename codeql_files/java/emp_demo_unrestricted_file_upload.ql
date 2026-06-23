/**
 * @name Employee Unrestricted File Upload
 * @description CWE-434: Detects Spring upload handlers that accept MultipartFile and write files without validating content or type.
 * @id custom/java/emp-demo-unrestricted-file-upload
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-434
 * @problem.severity error
 */

import java

from Method m, Parameter p, MethodCall copyCall
where
  p = m.getAParameter() and
 p.getType().getErasure() instanceof RefType and
  p.getType().getErasure().(RefType).hasQualifiedName(
    "org.springframework.web.multipart",
    "MultipartFile"
  ) and 
 copyCall.getEnclosingCallable() = m and
  copyCall.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
  copyCall.getMethod().hasName("copy")
select copyCall, "MultipartFile is written to disk. Check file type validation and storage policy."
