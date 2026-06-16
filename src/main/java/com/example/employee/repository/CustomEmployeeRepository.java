package com.example.employee.repository;

public interface CustomEmployeeRepository {
    void logTenant(String customTenantId);
    void deleteByIdentifier(String employeeIdentifier);
}
