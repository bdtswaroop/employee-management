package com.example.employee.service;

import com.example.employee.entity.Employee;
import com.example.employee.repository.CustomEmployeeRepository;
import com.example.employee.repository.EmployeeRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Instant;

@RequiredArgsConstructor
@Service
public class EmployeeService {

    private final EmployeeRepository employeeRepository;

    private final CustomEmployeeRepository customEmployeeRepository;

    private final Path uploadRoot = Paths.get("uploads");

     @Transactional
    public Employee createEmployee(String name, String email, String department, String customTenantId, MultipartFile file) throws IOException {
        // Unsafe propagation: concatenate tenant id into audit string
        //String audit = "audit_for_tenant=" + customTenantId;

        Employee e = new Employee();
        e.setName(name);
        e.setEmail(email);
        e.setDepartment(department);
        // use raw customTenantId as part of internal code routing - intentionally unsafe
        e.setInternalCode(name + "-" + customTenantId + "-" + Instant.now().toEpochMilli());

        String filename = null;
        if (file != null && !file.isEmpty()) {
            // Ensure uploads directory exists
            Files.createDirectories(uploadRoot);

            filename = Instant.now().toEpochMilli() + "_" + file.getOriginalFilename();
            Path target = uploadRoot.resolve(filename);
            // Ensure parent exists and write via stream to avoid cross-filesystem move issues
            Files.createDirectories(target.getParent());
            try (java.io.InputStream in = file.getInputStream()) {
                Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
            }
            // Store relative filename so the app can serve it under /uploads/{filename}
            e.setProfilePicturePath(filename);
        } else {
            e.setProfilePicturePath(null);
        }

        Employee saved = employeeRepository.save(e);

        // Pass raw tenant id into custom repo sink (unsafe)
        customEmployeeRepository.logTenant(customTenantId);

        return saved;
    }

    public void deleteEmployee(String employeeIdentifier) {
        // Propagate raw input to the custom repository which performs unsafe concatenation
        customEmployeeRepository.deleteByIdentifier(employeeIdentifier);

        // attempt to remove from JPA-managed store as well (best-effort)
        employeeRepository.findByInternalCode(employeeIdentifier).ifPresent(employeeRepository::delete);
    }
}
