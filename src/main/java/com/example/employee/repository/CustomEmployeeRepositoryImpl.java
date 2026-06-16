package com.example.employee.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;


@Repository
public class CustomEmployeeRepositoryImpl implements CustomEmployeeRepository {

    @PersistenceContext
    private EntityManager entityManager;

    // @Transactional
    // @Override
    // public void logTenant(String customTenantId) {
    //     // Unsafe concatenation sink: vulnerable to SQL injection
    //     String sql = "INSERT INTO upload_logs (tenant) VALUES ('" + customTenantId + "')";
    //     entityManager.createNativeQuery(sql).executeUpdate();
    // }

    //fixed code
    @Transactional
    @Override
    public void logTenant(String customTenantId) {
        //CWE-89: SQL Injection via customTenantId in logTenant fix
        String sql = "INSERT INTO upload_logs (tenant) VALUES (:tenant)";
    
        entityManager.createNativeQuery(sql)
            .setParameter("tenant", customTenantId)
            .executeUpdate();
    }

    @Override
    public void deleteByIdentifier(String employeeIdentifier) {
        // Unsafe deletion sink: vulnerable to SQL injection
        String del = "DELETE FROM employees WHERE internal_code = '" + employeeIdentifier + "'";
        entityManager.createNativeQuery(del).executeUpdate();
    }
}
