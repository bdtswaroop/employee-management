package com.example.employee.controller;

import com.example.employee.entity.Employee;
import com.example.employee.entity.EmployeeDocument;
import com.example.employee.repository.EmployeeRepository;
import com.example.employee.service.EmployeeService;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.core.io.Resource;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@RequiredArgsConstructor
@RestController
public class EmployeeController {

    private final EmployeeService employeeService;

    private final EmployeeRepository employeeRepository;
    //CWE-89: SQL Injection via customTenantId in logTenant fix
    private static final Pattern TENANT_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,50}$");

    @PostMapping("/api/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        if ("emp1".equals(username) && "123456".equals(password)) {
            return ResponseEntity.ok(Map.of(
                    "authenticated", true,
                    "username", username
            ));
        }

        return ResponseEntity.status(401).body(Map.of(
                "authenticated", false,
                "message", "Invalid username or password"
        ));
    }

    @PostMapping(path = "/api/employees/upload", consumes = {"multipart/form-data"})
    public ResponseEntity<Employee> uploadEmployee(@RequestParam(value = "file", required = false) MultipartFile file,
                                                   @RequestParam("name") String name,
                                                   @RequestParam("email") String email,
                                                   @RequestParam("department") String department,
                                                   @RequestParam("custom_tenant_id") String customTenantId) throws IOException {
   
        // Fixed code                                                
        if (customTenantId == null || !TENANT_ID_PATTERN.matcher(customTenantId).matches()) {
           throw new IllegalArgumentException("Invalid tenant id");
        // CWE-209: Uncomment to test: emp-demo-error-message-user-input
        // throw new IllegalArgumentException("Invalid tenant id: " + customTenantId);
        }
                                                    // Pass raw user-provided custom_tenant_id directly into service (no validation)
        Employee saved = employeeService.createEmployee(name, email, department, customTenantId, file);
        return ResponseEntity.ok(saved);
    }

    @DeleteMapping("/api/employees/delete")
    public ResponseEntity<String> deleteEmployee(@RequestParam("employeeIdentifier") String employeeIdentifier) {
        // Pass raw employeeIdentifier directly to service (no validation)
        employeeService.deleteEmployee(employeeIdentifier);
        return ResponseEntity.ok("Deleted (or attempted) identifier: " + employeeIdentifier);
    }

    @GetMapping("/api/employees")
    public List<Employee> listEmployees() {
        return employeeRepository.findAll();
    }

    @GetMapping("/api/employees/{id}")
    public ResponseEntity<Employee> getEmployee(@PathVariable Long id) {
        return employeeRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping(path = "/api/employees/{id}/documents", consumes = {"multipart/form-data"})
    public ResponseEntity<EmployeeDocument> uploadEmployeeDocument(@PathVariable Long id,
                                                                  @RequestParam("document") MultipartFile document,
                                                                  @RequestParam(value = "documentName", required = false) String documentName) throws IOException {
        EmployeeDocument saved = employeeService.addEmployeeDocument(id, document, documentName);
        return ResponseEntity.ok(saved);
    }

    @GetMapping("/api/employees/{id}/documents")
    public List<EmployeeDocument> listEmployeeDocuments(@PathVariable Long id) {
        return employeeService.listEmployeeDocuments(id);
    }

    @GetMapping("/uploads/{filename:.+}")
    public ResponseEntity<Resource> serveUpload(@PathVariable String filename) throws MalformedURLException {
       return employeeService.uploadFile(filename);
    }
}
