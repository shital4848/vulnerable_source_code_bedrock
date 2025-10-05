package com.ecommerce.models;

import java.util.*;
import java.io.Serializable;
import java.math.BigDecimal;

/**
 * Vulnerable User model with multiple security issues
 */
public class User implements Serializable {
    
    // VULNERABILITY: Serializable without serialVersionUID
    // private static final long serialVersionUID = 1L;
    
    // VULNERABILITY: Public fields allow direct access
    public String userId;
    public String username;
    public String password;  // VULNERABILITY: Plain text password storage
    public String email;
    public String socialSecurityNumber;  // VULNERABILITY: Sensitive data
    public String creditCardNumber;      // VULNERABILITY: PCI compliance issue
    public Date birthDate;
    public String homeAddress;
    public String phoneNumber;
    
    // VULNERABILITY: Admin privileges as simple boolean
    public boolean isAdmin;
    public boolean isActive;
    
    // VULNERABILITY: Financial data without proper protection
    public BigDecimal accountBalance;
    public List<String> transactionHistory;
    
    // VULNERABILITY: Security questions in plain text
    public Map<String, String> securityQuestions;
    
    // VULNERABILITY: Session data mixed with user data
    public String sessionToken;
    public Date lastLoginTime;
    public String lastLoginIP;
    
    /**
     * VULNERABILITY: Constructor with too many parameters, no validation
     */
    public User(String userId, String username, String password, String email, 
                String ssn, String ccNumber, Date birthDate, String address, 
                String phone, boolean isAdmin) {
        // VULNERABILITY: No input validation
        this.userId = userId;
        this.username = username;
        this.password = password;  // Should be hashed
        this.email = email;
        this.socialSecurityNumber = ssn;
        this.creditCardNumber = ccNumber;
        this.birthDate = birthDate;
        this.homeAddress = address;
        this.phoneNumber = phone;
        this.isAdmin = isAdmin;
        this.isActive = true;
        this.accountBalance = BigDecimal.ZERO;
        this.transactionHistory = new ArrayList<>();
        this.securityQuestions = new HashMap<>();
    }
    
    /**
     * VULNERABILITY: Default constructor allows uninitialized objects
     */
    public User() {
        // VULNERABILITY: No default values set
    }
    
    /**
     * VULNERABILITY: Password validation is weak
     */
    public boolean isPasswordValid(String inputPassword) {
        // VULNERABILITY: Plain text password comparison
        return this.password != null && this.password.equals(inputPassword);
    }
    
    /**
     * VULNERABILITY: Sensitive data in toString()
     */
    @Override
    public String toString() {
        return "User{" +
                "userId='" + userId + '\'' +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +  // VULNERABILITY: Password in string representation
                ", email='" + email + '\'' +
                ", socialSecurityNumber='" + socialSecurityNumber + '\'' +  // VULNERABILITY: SSN exposed
                ", creditCardNumber='" + creditCardNumber + '\'' +  // VULNERABILITY: Credit card exposed
                ", birthDate=" + birthDate +
                ", homeAddress='" + homeAddress + '\'' +
                ", phoneNumber='" + phoneNumber + '\'' +
                ", isAdmin=" + isAdmin +
                ", isActive=" + isActive +
                ", accountBalance=" + accountBalance +
                ", sessionToken='" + sessionToken + '\'' +  // VULNERABILITY: Session token exposed
                '}';
    }
    
    /**
     * VULNERABILITY: Equals method doesn't validate properly
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        
        User user = (User) obj;
        
        // VULNERABILITY: Comparing sensitive fields
        return Objects.equals(password, user.password) &&  // Should never compare passwords directly
               Objects.equals(socialSecurityNumber, user.socialSecurityNumber);
    }
    
    /**
     * VULNERABILITY: HashCode includes sensitive data
     */
    @Override
    public int hashCode() {
        // VULNERABILITY: Including sensitive fields in hash
        return Objects.hash(username, password, socialSecurityNumber, creditCardNumber);
    }
    
    /**
     * VULNERABILITY: Privilege escalation possible
     */
    public void setAdminStatus(boolean admin) {
        // VULNERABILITY: No authorization check
        this.isAdmin = admin;
        System.out.println("Admin status changed for user " + username + " to: " + admin);
    }
    
    /**
     * VULNERABILITY: Direct financial manipulation
     */
    public void updateBalance(BigDecimal amount) {
        // VULNERABILITY: No validation, can set negative amounts
        this.accountBalance = amount;
        
        // VULNERABILITY: Financial transaction without audit log
        String transaction = "Balance updated to: " + amount + " at " + new Date();
        this.transactionHistory.add(transaction);
        
        System.out.println("Balance updated for user " + username + " to: " + amount);
    }
    
    /**
     * VULNERABILITY: Information disclosure method
     */
    public String getDetailedUserInfo() {
        StringBuilder info = new StringBuilder();
        info.append("User Details:\n");
        info.append("ID: ").append(userId).append("\n");
        info.append("Username: ").append(username).append("\n");
        info.append("Password: ").append(password).append("\n");  // VULNERABILITY: Password exposure
        info.append("Email: ").append(email).append("\n");
        info.append("SSN: ").append(socialSecurityNumber).append("\n");  // VULNERABILITY: SSN exposure
        info.append("Credit Card: ").append(creditCardNumber).append("\n");  // VULNERABILITY: CC exposure
        info.append("Address: ").append(homeAddress).append("\n");
        info.append("Phone: ").append(phoneNumber).append("\n");
        info.append("Admin: ").append(isAdmin).append("\n");
        info.append("Balance: ").append(accountBalance).append("\n");
        info.append("Session: ").append(sessionToken).append("\n");  // VULNERABILITY: Session token exposure
        
        return info.toString();
    }
    
    /**
     * VULNERABILITY: Unsafe cloning method
     */
    public User clone() {
        // VULNERABILITY: Shallow copy of sensitive data
        User cloned = new User();
        cloned.userId = this.userId;
        cloned.username = this.username;
        cloned.password = this.password;  // VULNERABILITY: Password copied
        cloned.email = this.email;
        cloned.socialSecurityNumber = this.socialSecurityNumber;  // VULNERABILITY: SSN copied
        cloned.creditCardNumber = this.creditCardNumber;  // VULNERABILITY: CC copied
        cloned.birthDate = this.birthDate;
        cloned.homeAddress = this.homeAddress;
        cloned.phoneNumber = this.phoneNumber;
        cloned.isAdmin = this.isAdmin;
        cloned.isActive = this.isActive;
        cloned.accountBalance = this.accountBalance;
        cloned.transactionHistory = new ArrayList<>(this.transactionHistory);  // VULNERABILITY: Transaction history copied
        cloned.securityQuestions = new HashMap<>(this.securityQuestions);  // VULNERABILITY: Security questions copied
        cloned.sessionToken = this.sessionToken;  // VULNERABILITY: Session token copied
        cloned.lastLoginTime = this.lastLoginTime;
        cloned.lastLoginIP = this.lastLoginIP;
        
        return cloned;
    }
    
    /**
     * VULNERABILITY: Method allows setting any user data without validation
     */
    public void updateUserData(Map<String, Object> userData) {
        // VULNERABILITY: No input validation or authorization
        for (Map.Entry<String, Object> entry : userData.entrySet()) {
            String field = entry.getKey();
            Object value = entry.getValue();
            
            // VULNERABILITY: Direct field manipulation based on string keys
            switch (field) {
                case "username":
                    this.username = (String) value;
                    break;
                case "password":
                    this.password = (String) value;  // VULNERABILITY: Direct password setting
                    break;
                case "email":
                    this.email = (String) value;
                    break;
                case "isAdmin":
                    this.isAdmin = (Boolean) value;  // VULNERABILITY: Admin privilege change
                    break;
                case "accountBalance":
                    this.accountBalance = (BigDecimal) value;  // VULNERABILITY: Financial data change
                    break;
                case "socialSecurityNumber":
                    this.socialSecurityNumber = (String) value;  // VULNERABILITY: SSN change
                    break;
                case "creditCardNumber":
                    this.creditCardNumber = (String) value;  // VULNERABILITY: CC change
                    break;
            }
        }
        
        System.out.println("User data updated for: " + username);
    }
    
    // VULNERABILITY: Getters expose sensitive data without protection
    public String getPassword() {
        return password;  // VULNERABILITY: Password getter
    }
    
    public String getSocialSecurityNumber() {
        return socialSecurityNumber;  // VULNERABILITY: SSN getter
    }
    
    public String getCreditCardNumber() {
        return creditCardNumber;  // VULNERABILITY: Credit card getter
    }
    
    public String getSessionToken() {
        return sessionToken;  // VULNERABILITY: Session token getter
    }
    
    public Map<String, String> getSecurityQuestions() {
        return securityQuestions;  // VULNERABILITY: Security questions getter
    }
    
    public List<String> getTransactionHistory() {
        return transactionHistory;  // VULNERABILITY: Financial history getter
    }
}