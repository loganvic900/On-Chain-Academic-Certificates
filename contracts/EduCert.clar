;; EduCert - On-Chain Academic Certificates
;; A tamper-proof system for issuing and verifying academic certificates

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u401))
(define-constant ERR-NOT-FOUND (err u404))
(define-constant ERR-ALREADY-EXISTS (err u409))
(define-constant ERR-INVALID-INPUT (err u400))
(define-constant ERR-CERTIFICATE-REVOKED (err u410))

(define-data-var next-certificate-id uint u1)

(define-map authorized-institutions principal bool)

(define-map certificates
    { certificate-id: uint }
    {
        student-address: principal,
        institution: principal,
        course-name: (string-ascii 100),
        degree-type: (string-ascii 50),
        graduation-date: uint,
        gpa: uint,
        issue-date: uint,
        is-revoked: bool,
        metadata-uri: (optional (string-ascii 200))
    }
)

(define-map student-certificates principal (list 50 uint))

(define-map institution-certificates principal (list 1000 uint))

(define-map certificate-hashes
    { hash: (buff 32) }
    { certificate-id: uint }
)

(define-data-var revocation-event-counter uint u0)

(define-map revocation-events
    { event-id: uint }
    {
        revoker: principal,
        timestamp: uint,
        certificates-count: uint
    }
)

(define-map certificate-revocation-link
    { certificate-id: uint }
    { event-id: uint }
)

(define-read-only (get-contract-owner)
    CONTRACT-OWNER
)

(define-read-only (is-authorized-institution (institution principal))
    (default-to false (map-get? authorized-institutions institution))
)

(define-read-only (get-revocation-event (event-id uint))
    (map-get? revocation-events { event-id: event-id })
)

(define-read-only (get-total-revocation-events)
    (var-get revocation-event-counter)
)

(define-read-only (get-certificate-revocation-event (certificate-id uint))
    (map-get? certificate-revocation-link { certificate-id: certificate-id })
)

(define-read-only (get-certificate (certificate-id uint))
    (map-get? certificates { certificate-id: certificate-id })
)

(define-read-only (get-student-certificates (student principal))
    (default-to (list) (map-get? student-certificates student))
)

(define-read-only (get-institution-certificates (institution principal))
    (default-to (list) (map-get? institution-certificates institution))
)

(define-read-only (verify-certificate-hash (hash (buff 32)))
    (map-get? certificate-hashes { hash: hash })
)

(define-read-only (is-certificate-valid (certificate-id uint))
    (match (get-certificate certificate-id)
        certificate (not (get is-revoked certificate))
        false
    )
)

(define-read-only (get-next-certificate-id)
    (var-get next-certificate-id)
)

(define-read-only (calculate-certificate-hash (certificate-id uint) (student-address principal) (course-name (string-ascii 100)) (degree-type (string-ascii 50)))
    (keccak256 (concat
        (concat
            (unwrap-panic (to-consensus-buff? certificate-id))
            (unwrap-panic (to-consensus-buff? student-address))
        )
        (concat
            (unwrap-panic (to-consensus-buff? course-name))
            (unwrap-panic (to-consensus-buff? degree-type))
        )
    ))
)

(define-public (authorize-institution (institution principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (ok (map-set authorized-institutions institution true))
    )
)

(define-public (revoke-institution-authorization (institution principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (ok (map-set authorized-institutions institution false))
    )
)

(define-public (issue-certificate 
    (student-address principal)
    (course-name (string-ascii 100))
    (degree-type (string-ascii 50))
    (graduation-date uint)
    (gpa uint)
    (metadata-uri (optional (string-ascii 200)))
)
    (let 
        (
            (certificate-id (var-get next-certificate-id))
            (current-block stacks-block-height)
            (institution tx-sender)
            (certificate-hash (calculate-certificate-hash certificate-id student-address course-name degree-type))
        )
        (asserts! (is-authorized-institution institution) ERR-UNAUTHORIZED)
        (asserts! (<= gpa u400) ERR-INVALID-INPUT)
        (asserts! (> (len course-name) u0) ERR-INVALID-INPUT)
        (asserts! (> (len degree-type) u0) ERR-INVALID-INPUT)
        (asserts! (<= graduation-date current-block) ERR-INVALID-INPUT)
        
        (map-set certificates 
            { certificate-id: certificate-id }
            {
                student-address: student-address,
                institution: institution,
                course-name: course-name,
                degree-type: degree-type,
                graduation-date: graduation-date,
                gpa: gpa,
                issue-date: current-block,
                is-revoked: false,
                metadata-uri: metadata-uri
            }
        )
        
        (map-set certificate-hashes 
            { hash: certificate-hash }
            { certificate-id: certificate-id }
        )
        
        (let ((student-certs (get-student-certificates student-address)))
            (map-set student-certificates student-address
                (unwrap-panic (as-max-len? (append student-certs certificate-id) u50))
            )
        )
        
        (let ((institution-certs (get-institution-certificates institution)))
            (map-set institution-certificates institution
                (unwrap-panic (as-max-len? (append institution-certs certificate-id) u1000))
            )
        )
        
        (var-set next-certificate-id (+ certificate-id u1))
        (ok certificate-id)
    )
)

(define-public (revoke-certificates-batch (certificate-ids (list 20 uint)))
    (let
        (
            (list-length (len certificate-ids))
            (caller tx-sender)
            (current-block stacks-block-height)
            (event-id (var-get revocation-event-counter))
        )
        (asserts! (or (is-eq caller CONTRACT-OWNER) (is-authorized-institution caller)) ERR-UNAUTHORIZED)
        (asserts! (> list-length u0) ERR-INVALID-INPUT)
        (asserts! (<= list-length u20) ERR-INVALID-INPUT)
        
        (fold revoke-and-link certificate-ids u0)
        
        (map-set revocation-events
            { event-id: event-id }
            {
                revoker: caller,
                timestamp: current-block,
                certificates-count: list-length
            }
        )
        
        (var-set revocation-event-counter (+ event-id u1))
        (ok event-id)
    )
)

(define-private (revoke-and-link (cert-id uint) (count uint))
    (match (get-certificate cert-id)
        certificate
        (if (not (get is-revoked certificate))
            (begin
                (map-set certificates
                    { certificate-id: cert-id }
                    (merge certificate { is-revoked: true })
                )
                (map-set certificate-revocation-link
                    { certificate-id: cert-id }
                    { event-id: (var-get revocation-event-counter) }
                )
                (+ count u1)
            )
            count
        )
        count
    )
)

(define-public (revoke-certificate (certificate-id uint))
    (let ((certificate (unwrap! (get-certificate certificate-id) ERR-NOT-FOUND)))
        (asserts! (or 
            (is-eq tx-sender CONTRACT-OWNER)
            (is-eq tx-sender (get institution certificate))
        ) ERR-UNAUTHORIZED)
        (asserts! (not (get is-revoked certificate)) ERR-CERTIFICATE-REVOKED)
        
        (ok (map-set certificates 
            { certificate-id: certificate-id }
            (merge certificate { is-revoked: true })
        ))
    )
)

(define-public (update-certificate-metadata (certificate-id uint) (new-metadata-uri (string-ascii 200)))
    (let ((certificate (unwrap! (get-certificate certificate-id) ERR-NOT-FOUND)))
        (asserts! (is-eq tx-sender (get institution certificate)) ERR-UNAUTHORIZED)
        (asserts! (not (get is-revoked certificate)) ERR-CERTIFICATE-REVOKED)
        
        (ok (map-set certificates 
            { certificate-id: certificate-id }
            (merge certificate { metadata-uri: (some new-metadata-uri) })
        ))
    )
)

(define-read-only (verify-certificate-ownership (certificate-id uint) (student principal))
    (match (get-certificate certificate-id)
        certificate (is-eq (get student-address certificate) student)
        false
    )
)

(define-read-only (get-certificate-details (certificate-id uint))
    (let ((certificate (unwrap! (get-certificate certificate-id) ERR-NOT-FOUND)))
        (ok {
            certificate-id: certificate-id,
            student-address: (get student-address certificate),
            institution: (get institution certificate),
            course-name: (get course-name certificate),
            degree-type: (get degree-type certificate),
            graduation-date: (get graduation-date certificate),
            gpa: (get gpa certificate),
            issue-date: (get issue-date certificate),
            is-revoked: (get is-revoked certificate),
            metadata-uri: (get metadata-uri certificate),
            is-valid: (and (not (get is-revoked certificate)) true)
        })
    )
)

(define-read-only (get-certificates-by-institution (institution principal))
    (get-institution-certificates institution)
)

(define-read-only (get-certificates-by-student (student principal))
    (get-student-certificates student)
)

(define-read-only (verify-certificate-authenticity (certificate-id uint) (expected-hash (buff 32)))
    (let ((certificate (unwrap! (get-certificate certificate-id) ERR-NOT-FOUND)))
        (let ((calculated-hash (calculate-certificate-hash 
            certificate-id
            (get student-address certificate)
            (get course-name certificate)
            (get degree-type certificate)
        )))
            (ok (is-eq calculated-hash expected-hash))
        )
    )
)

(define-read-only (get-certificate-statistics)
    (let ((total-certificates (- (var-get next-certificate-id) u1)))
        (ok {
            total-certificates: total-certificates,
            current-block: stacks-block-height
        })
    )
)

(define-public (transfer-certificate-ownership (certificate-id uint) (new-owner principal))
    (let ((certificate (unwrap! (get-certificate certificate-id) ERR-NOT-FOUND)))
        (asserts! (is-eq tx-sender (get student-address certificate)) ERR-UNAUTHORIZED)
        (asserts! (not (get is-revoked certificate)) ERR-CERTIFICATE-REVOKED)
        
        (map-set certificates 
            { certificate-id: certificate-id }
            (merge certificate { student-address: new-owner })
        )
        
        (ok true)
    )
)

(define-read-only (batch-verify-certificates (certificate-ids (list 20 uint)))
    (map verify-certificate-validity certificate-ids)
)

(define-private (verify-certificate-validity (cert-id uint))
    {
        certificate-id: cert-id,
        is-valid: (is-certificate-valid cert-id),
        exists: (is-some (get-certificate cert-id))
    }
)
