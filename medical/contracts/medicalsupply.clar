;; Medical Supply Authentication
;; A smart contract for tracking and verifying the authenticity of medical supplies

;; Define constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-authorized (err u101))
(define-constant err-product-exists (err u102))
(define-constant err-product-not-found (err u103))
(define-constant err-invalid-role (err u104))
(define-constant err-invalid-transfer (err u105))
(define-constant err-invalid-input (err u106))
(define-constant err-invalid-date (err u107))

;; Define roles
(define-constant role-manufacturer u1)
(define-constant role-distributor u2)
(define-constant role-healthcare-provider u3)

;; Data maps
;; Map to store entity roles (address -> role)
(define-map entity-roles principal uint)

;; Map to store product information
(define-map products
  { product-id: (string-ascii 36) }
  {
    name: (string-ascii 64),
    manufacturer: principal,
    current-owner: principal,
    manufacturing-date: uint,
    expiry-date: uint,
    batch-number: (string-ascii 32),
    is-active: bool
  }
)

;; Map to store supply chain events
(define-map supply-chain-events
  { product-id: (string-ascii 36), event-index: uint }
  {
    handler: principal,
    handler-role: uint,
    location: (string-ascii 64),
    timestamp: uint,
    notes: (string-utf8 256)
  }
)

;; Map to track event count per product
(define-map product-event-count
  { product-id: (string-ascii 36) }
  { count: uint }
)

;; Read-only functions

;; Check if caller has a specific role
(define-read-only (has-role (role uint))
  (match (map-get? entity-roles tx-sender)
    role-value (is-eq role-value role)
    false
  )
)

;; Validate role
(define-read-only (is-valid-role (role uint))
  (or (is-eq role role-manufacturer) (is-eq role role-distributor) (is-eq role role-healthcare-provider))
)

;; Get product details
(define-read-only (get-product (product-id (string-ascii 36)))
  (map-get? products { product-id: product-id })
)

;; Get supply chain event
(define-read-only (get-supply-chain-event (product-id (string-ascii 36)) (event-index uint))
  (map-get? supply-chain-events { product-id: product-id, event-index: event-index })
)

;; Get event count for a product
(define-read-only (get-event-count (product-id (string-ascii 36)))
  (default-to { count: u0 } (map-get? product-event-count { product-id: product-id }))
)

;; Verify product authenticity
(define-read-only (verify-product-authenticity (product-id (string-ascii 36)))
  (match (map-get? products { product-id: product-id })
    product { 
      is-authentic: (get is-active product),
      manufacturer: (get manufacturer product),
      current-owner: (get current-owner product),
      expiry-date: (get expiry-date product)
    }
    { is-authentic: false, manufacturer: contract-owner, current-owner: contract-owner, expiry-date: u0 }
  )
)

;; Validate product ID is not empty
(define-read-only (is-valid-product-id (product-id (string-ascii 36)))
  (not (is-eq product-id ""))
)

;; Validate name is not empty
(define-read-only (is-valid-name (name (string-ascii 64)))
  (not (is-eq name ""))
)

;; Validate batch number is not empty
(define-read-only (is-valid-batch-number (batch-number (string-ascii 32)))
  (not (is-eq batch-number ""))
)

;; Validate location is not empty
(define-read-only (is-valid-location (location (string-ascii 64)))
  (not (is-eq location ""))
)

;; Validate dates (expiry must be after manufacturing)
(define-read-only (is-valid-dates (manufacturing-date uint) (expiry-date uint))
  (> expiry-date manufacturing-date)
)

;; Public functions

;; Set entity role (owner only)
(define-public (set-entity-role (entity principal) (role uint))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (is-valid-role role) err-invalid-role)
    (ok (map-set entity-roles entity role))
  )
)

;; Register new product (manufacturer only)
(define-public (register-product 
    (product-id (string-ascii 36))
    (name (string-ascii 64))
    (manufacturing-date uint)
    (expiry-date uint)
    (batch-number (string-ascii 32))
    (location (string-ascii 64))
    (notes (string-utf8 256))
  )
  (let
    (
      (manufacturer tx-sender)
      (validated-product-id product-id)
      (validated-name name)
      (validated-manufacturing-date manufacturing-date)
      (validated-expiry-date expiry-date)
      (validated-batch-number batch-number)
      (validated-location location)
      (validated-notes notes)
    )
    ;; Validate inputs
    (asserts! (has-role role-manufacturer) err-not-authorized)
    (asserts! (is-valid-product-id validated-product-id) err-invalid-input)
    (asserts! (is-valid-name validated-name) err-invalid-input)
    (asserts! (is-valid-batch-number validated-batch-number) err-invalid-input)
    (asserts! (is-valid-location validated-location) err-invalid-input)
    (asserts! (is-valid-dates validated-manufacturing-date validated-expiry-date) err-invalid-date)
    (asserts! (is-none (map-get? products { product-id: validated-product-id })) err-product-exists)
    
    ;; Set product information
    (map-set products
      { product-id: validated-product-id }
      {
        name: validated-name,
        manufacturer: manufacturer,
        current-owner: manufacturer,
        manufacturing-date: validated-manufacturing-date,
        expiry-date: validated-expiry-date,
        batch-number: validated-batch-number,
        is-active: true
      }
    )
    
    ;; Record initial supply chain event
    (map-set supply-chain-events
      { product-id: validated-product-id, event-index: u0 }
      {
        handler: manufacturer,
        handler-role: role-manufacturer,
        location: validated-location,
        timestamp: stacks-block-height,
        notes: validated-notes
      }
    )
    
    ;; Set event count to 1
    (map-set product-event-count
      { product-id: validated-product-id }
      { count: u1 }
    )
    
    (ok true)
  )
)

;; Record supply chain event (authorized entities only)
(define-public (record-supply-chain-event
    (product-id (string-ascii 36))
    (location (string-ascii 64))
    (notes (string-utf8 256))
  )
  (let
    (
      (handler tx-sender)
      (validated-product-id product-id)
      (validated-location location)
      (validated-notes notes)
      (handler-role (unwrap! (map-get? entity-roles handler) err-not-authorized))
      (product (unwrap! (map-get? products { product-id: validated-product-id }) err-product-not-found))
      (event-count (get count (get-event-count validated-product-id)))
      (new-event-index event-count)
    )
    
    ;; Validate inputs
    (asserts! (is-valid-product-id validated-product-id) err-invalid-input)
    (asserts! (is-valid-location validated-location) err-invalid-input)
    
    ;; Only current owner or authorized entities can record events
    (asserts! (or (is-eq handler (get current-owner product)) (has-role role-distributor) (has-role role-healthcare-provider)) err-not-authorized)
    
    ;; Record the supply chain event
    (map-set supply-chain-events
      { product-id: validated-product-id, event-index: new-event-index }
      {
        handler: handler,
        handler-role: handler-role,
        location: validated-location,
        timestamp: stacks-block-height,
        notes: validated-notes
      }
    )
    
    ;; Increment event count
    (map-set product-event-count
      { product-id: validated-product-id }
      { count: (+ event-count u1) }
    )
    
    (ok true)
  )
)

;; Transfer product ownership
(define-public (transfer-ownership
    (product-id (string-ascii 36))
    (new-owner principal)
    (location (string-ascii 64))
    (notes (string-utf8 256))
  )
  (let
    (
      (current-handler tx-sender)
      (validated-product-id product-id)
      (validated-location location)
      (validated-notes notes)
      (handler-role (unwrap! (map-get? entity-roles current-handler) err-not-authorized))
      (product (unwrap! (map-get? products { product-id: validated-product-id }) err-product-not-found))
      (event-count (get count (get-event-count validated-product-id)))
      (new-event-index event-count)
    )
    
    ;; Validate inputs
    (asserts! (is-valid-product-id validated-product-id) err-invalid-input)
    (asserts! (is-valid-location validated-location) err-invalid-input)
    
    ;; Only current owner can transfer ownership
    (asserts! (is-eq current-handler (get current-owner product)) err-not-authorized)
    
    ;; New owner must be an authorized entity
    (asserts! (is-some (map-get? entity-roles new-owner)) err-not-authorized)
    
    ;; Update product ownership
    (map-set products
      { product-id: validated-product-id }
      (merge product { current-owner: new-owner })
    )
    
    ;; Record the transfer event
    (map-set supply-chain-events
      { product-id: validated-product-id, event-index: new-event-index }
      {
        handler: current-handler,
        handler-role: handler-role,
        location: validated-location,
        timestamp: stacks-block-height,
        notes: validated-notes
      }
    )
    
    ;; Increment event count
    (map-set product-event-count
      { product-id: validated-product-id }
      { count: (+ event-count u1) }
    )
    
    (ok true)
  )
)

