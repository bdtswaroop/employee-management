package com.example.employee.service;

import com.example.employee.entity.Employee;
import com.example.employee.entity.EmployeeDocument;
import com.example.employee.repository.CustomEmployeeRepository;
import com.example.employee.repository.EmployeeDocumentRepository;
import com.example.employee.repository.EmployeeRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;


import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.List;

@RequiredArgsConstructor
@Service
public class EmployeeService {

    private final EmployeeRepository employeeRepository;

    private final EmployeeDocumentRepository employeeDocumentRepository;

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
        e.setCustomTenantId(customTenantId);
        // use raw customTenantId as part of internal code routing - intentionally unsafe
        e.setInternalCode(name + "-" + customTenantId + "-" + Instant.now().toEpochMilli());

        String filename = null;
        if (file != null && !file.isEmpty()) {
            filename = storeUpload(file);
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

    @Transactional
    public EmployeeDocument addEmployeeDocument(Long employeeId, MultipartFile file, String documentName) throws IOException {
        Employee employee = employeeRepository.findById(employeeId)
                .orElseThrow(() -> new IllegalArgumentException("Employee not found: " + employeeId));

        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Document file is required");
            // CWE-209: Uncomment to test: emp-demo-error-message-user-input
            // throw new IllegalArgumentException("Document file is required:"+ file);

        }

        String filename = storeUpload(file);
        EmployeeDocument document = new EmployeeDocument();
        document.setEmployee(employee);
        document.setDocumentName(documentName == null || documentName.isBlank()
                ? file.getOriginalFilename()
                : documentName);
        document.setDocumentPath(filename);
        document.setContentType(file.getContentType());
        document.setSizeBytes(file.getSize());
        document.setUploadedAt(Instant.now());

        return employeeDocumentRepository.save(document);
    }

    public List<EmployeeDocument> listEmployeeDocuments(Long employeeId) {
        return employeeDocumentRepository.findByEmployeeId(employeeId);
    }

    public void deleteEmployee(String employeeIdentifier) {
        // Propagate raw input to the custom repository which performs unsafe concatenation
        customEmployeeRepository.deleteByIdentifier(employeeIdentifier);

        // attempt to remove from JPA-managed store as well (best-effort)
        employeeRepository.findByInternalCode(employeeIdentifier).ifPresent(employeeRepository::delete);
    }

    public ResponseEntity<Resource> uploadFile(String filename) throws MalformedURLException {       
        Path file = sanitizeFilename(filename);
        Resource resource = new UrlResource(file.toUri());
        if (!resource.exists()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + resource.getFilename() + "\"")
                .body(resource);
    }

    private static final Path UPLOAD_ROOT =
            Paths.get("uploads").toAbsolutePath().normalize();

     //CWE-22: Path Traversal via upload file fix
    public static Path sanitizeFilename(String filename) {

        Path resolved = UPLOAD_ROOT.resolve(filename)
                                   .normalize()
                                   .toAbsolutePath();

        if (!resolved.startsWith(UPLOAD_ROOT)) {
            throw new IllegalArgumentException(
                    "Invalid filename: path traversal attempt");
        }

        return resolved;
    }

    //cwe-434: Unrestricted File Upload triggers here. 
    private String storeUpload(MultipartFile file) throws IOException {
        Files.createDirectories(uploadRoot);

        String filename = Instant.now().toEpochMilli() + "_" + file.getOriginalFilename();
        Path target = uploadRoot.resolve(filename);
        Files.createDirectories(target.getParent());
        try (java.io.InputStream in = file.getInputStream()) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        return filename;
    }
}
