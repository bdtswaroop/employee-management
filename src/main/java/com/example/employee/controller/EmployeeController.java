package com.example.employee.controller;

import com.example.employee.entity.Employee;
import com.example.employee.repository.EmployeeRepository;
import com.example.employee.service.EmployeeService;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;

@RequiredArgsConstructor
@RestController
public class EmployeeController {

    private final EmployeeService employeeService;

    private final EmployeeRepository employeeRepository;
    //CWE-89: SQL Injection via customTenantId in logTenant fix
    private static final Pattern TENANT_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,50}$");

    @PostMapping(path = "/api/employees/upload", consumes = {"multipart/form-data"})
    public ResponseEntity<Employee> uploadEmployee(@RequestParam(value = "file", required = false) MultipartFile file,
                                                   @RequestParam("name") String name,
                                                   @RequestParam("email") String email,
                                                   @RequestParam("department") String department,
                                                   @RequestParam("custom_tenant_id") String customTenantId) throws IOException {
   
        // Fixed code                                                
        if (customTenantId == null || !TENANT_ID_PATTERN.matcher(customTenantId).matches()) {
        throw new IllegalArgumentException("Invalid tenant id");
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

    @GetMapping("/uploads/{filename:.+}")
    public ResponseEntity<Resource> serveUpload(@PathVariable String filename) throws Exception {
        java.nio.file.Path file = java.nio.file.Paths.get("uploads").resolve(filename).normalize();
        Resource resource = new UrlResource(file.toUri());
        if (!resource.exists()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + resource.getFilename() + "\"")
                .body(resource);
    }
}
