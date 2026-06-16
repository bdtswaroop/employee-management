package com.example.employee.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "employees")
@Data
public class Employee {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String name;
    private String email;
    private String department;

    @Column(name = "internal_code")
    private String internalCode;

    @Column(name = "profile_path")
    private String profilePicturePath;
}
