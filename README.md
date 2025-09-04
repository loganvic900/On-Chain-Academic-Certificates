# 🎓 EduCert - On-Chain Academic Certificates

A tamper-proof smart contract system for issuing and verifying academic certificates and diplomas on the Stacks blockchain.

## 🌟 Features

- 📜 **Certificate Issuance**: Institutions can issue tamper-proof digital certificates
- 🔍 **Instant Verification**: Employers and third parties can verify certificate authenticity
- 🏛️ **Institution Management**: Only authorized institutions can issue certificates  
- 🔒 **Security**: Certificates are cryptographically secured and immutable
- 📊 **Batch Operations**: Verify multiple certificates at once
- 🔄 **Transfer Ownership**: Students can transfer certificate ownership
- ❌ **Revocation**: Institutions can revoke certificates if needed

## 🚀 Quick Start

### Prerequisites

- [Clarinet](https://github.com/hirosystems/clarinet) installed
- Stacks wallet for transaction signing

### 📋 Contract Functions

#### For Contract Owner
```clarity
;; Authorize an institution to issue certificates
(authorize-institution principal)

;; Revoke institution authorization
(revoke-institution-authorization principal)
```

#### For Institutions  
```clarity
;; Issue a new certificate
(issue-certificate student-address course-name degree-type graduation-date gpa metadata-uri)

;; Revoke a certificate
(revoke-certificate certificate-id)

;; Update certificate metadata
(update-certificate-metadata certificate-id new-metadata-uri)
```

#### For Students
```clarity
;; Transfer certificate ownership
(transfer-certificate-ownership certificate-id new-owner)
```

#### For Everyone (Read-Only)
```clarity
;; Get certificate details
(get-certificate-details certificate-id)

;; Verify certificate authenticity with hash
(verify-certificate-authenticity certificate-id expected-hash)

;; Check if certificate is valid (not revoked)
(is-certificate-valid certificate-id)

;; Get all certificates for a student
(get-certificates-by-student student-address)

;; Get certificates issued by institution
(get-certificates-by-institution institution-address limit offset)

;; Batch verify multiple certificates
(batch-verify-certificates certificate-ids)
```

## 💡 Usage Examples

### 1. Authorize an Institution
```clarity
;; Only contract owner can do this
(contract-call? .EduCert authorize-institution 'SP1ABC...INSTITUTION)
```

### 2. Issue a Certificate
```clarity
;; Institution issues certificate for student
(contract-call? .EduCert issue-certificate 
    'SP1XYZ...STUDENT 
    "Computer Science" 
    "Bachelor of Science" 
    u2024 
    u350 
    (some "ipfs://QmHash..."))
```

### 3. Verify a Certificate
```clarity
;; Anyone can verify certificate details
(contract-call? .EduCert get-certificate-details u1)

;; Verify with cryptographic hash
(contract-call? .EduCert verify-certificate-authenticity u1 0x123abc...)
```

### 4. Batch Verification
```clarity
;; Verify multiple certificates at once
(contract-call? .EduCert batch-verify-certificates (list u1 u2 u3))
```

## 📊 Data Structure

Each certificate contains:
- **Student Address**: The recipient's Stacks address
- **Institution**: The issuing institution's address
- **Course Name**: Name of the course/program (max 100 chars)
- **Degree Type**: Type of degree (max 50 chars)  
- **Graduation Date**: Block height when graduated
- **GPA**: Grade point average (0-400, representing 0.00-4.00)
- **Issue Date**: Block height when certificate was issued
- **Revocation Status**: Whether certificate is revoked
- **Metadata URI**: Optional link to additional certificate data

## 🔐 Security Features

- ✅ **Authorization Control**: Only approved institutions can issue certificates
- ✅ **Cryptographic Hashes**: Each certificate has a unique hash for verification
- ✅ **Immutable Records**: Certificates cannot be modified once issued
- ✅ **Revocation Support**: Institutions can revoke certificates if needed
- ✅ **Ownership Transfer**: Students control their certificate ownership

## 🧪 Testing

```bash
# Check contract syntax
clarinet check

# Run tests
clarinet test

# Start local development environment
clarinet console
```

## 📝 Error Codes

- `u401`: Unauthorized access
- `u404`: Certificate not found  
- `u409`: Certificate already exists
- `u400`: Invalid input parameters
- `u410`: Certificate already revoked

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Test your changes with `clarinet check`
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

---

Built with ❤️ using [Clarity](https://clarity-lang.org/) and [Stacks](https://www.stacks.co/)
