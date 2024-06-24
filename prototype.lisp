(load "~/quicklisp/setup.lisp")
(ql:quickload "ironclad")

(defpackage :bytes
  (:use :common-lisp)
  (:export :|| :i2osp :os2ip :strxor :ascii))
(defpackage :rfc9380
  (:use :common-lisp)
  (:import-from :bytes :|| :i2osp :os2ip :strxor :ascii))
(defpackage :hmac
  (:use :common-lisp)
  (:export :sha256))
(defpackage :hkdf
  (:use :common-lisp)
  (:import-from :bytes :i2osp :os2ip :||)
  (:export :extract :expand))
(defpackage :bl
  (:use :common-lisp)
  (:import-from :bytes :|| :ascii)
  (:import-from :crypto :ec-scalar-mult :+secp256r1-l+)
  (:export :keygen :generate-key-pair :blind-public-key :blind-private-key))
(defpackage :kem
  (:use :common-lisp)
  (:import-from :bytes :|| :ascii :i2osp :os2ip))
(defpackage :arkg
  (:use :common-lisp)
  (:import-from :bytes :|| :ascii))
(defpackage :hdk
  (:use :common-lisp))


(in-package :bytes)

(defun || (&rest bs) (apply #'concatenate '(vector (unsigned-byte 8)) bs))
(defun i2osp (i n) (crypto:integer-to-octets i :n-bits (* n 8)))
(defun os2ip (os) (crypto:octets-to-integer os))
(defun strxor (s1 s2) (map 'crypto::simple-octet-vector #'logxor s1 s2))
(defun ascii (s) (crypto:ascii-string-to-byte-array s))


(in-package :rfc9380)

(defun sha256 (&rest bs) (loop with hash = (crypto:make-digest :sha256)
                               for b in bs do (crypto:update-digest hash b)
                               finally (return (crypto:produce-digest hash))))
(defun expand-message-xmd (msg dst len)
  (loop with dst = (|| dst (i2osp (length dst) 1))
        with b = (make-array len :fill-pointer 0)
        with b0 = (sha256 (i2osp 0 64) msg (i2osp len 2) (i2osp 0 1) dst)
        for i from 1 upto (ceiling (/ len 32))
        for bi = (sha256 b0 (i2osp 1 1) dst)
          then (sha256 (strxor b0 bi) (i2osp i 1) dst)
        do (loop for j across bi do (vector-push j b))
        finally (return (coerce b 'crypto::simple-octet-vector))))

(loop with vectors = '(("" "QUUX-V01-CS02-with-expander-SHA256-128" #x20 #x68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235)
                       ("abc" "QUUX-V01-CS02-with-expander-SHA256-128" #x20 #xd8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615)
                       ("" "QUUX-V01-CS02-with-expander-SHA256-128" #x80 #xaf84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced))
      for (msg dst len result) in vectors
      do (assert (= (os2ip (expand-message-xmd (ascii msg) (ascii dst) len))
                    result)))

(defparameter *order* nil)
(defparameter *dst* nil)

(defun hash-to-field (msg)
  (mod (os2ip (expand-message-xmd msg *dst* 48)) *order*))


(in-package :bl)

(defparameter *dst-ext* (ascii "ARKG-P256MUL-ECDH"))
(define-condition keygen (condition) ())
(defun generate-key-pair () (restart-case (error 'keygen) (use-value (v) v)))
(defun blind (tau info)
  (let ((rfc9380::*dst* (|| (ascii "ARKG-BL-EC.") *dst-ext* info))
        (rfc9380::*order* +secp256r1-l+))
    (rfc9380::hash-to-field tau)))
(defun blind-public-key (pk tau info) (ec-scalar-mult pk (blind tau info)))
(defun blind-private-key (sk tau info) (* sk (blind tau info)))

(defun generate-with-crypto (c)
  (multiple-value-bind (s P) (crypto:generate-key-pair :secp256r1)
    (use-value (cons s P) c)))
(defun generate-static (c)
  (use-value (cons 1 2) c))
(handler-bind ((keygen #'generate-with-crypto)) (generate-key-pair))
(handler-bind ((keygen #'generate-static)) (generate-key-pair))


(in-package :hmac)

(defun sha256 (key &rest bs)
  (loop with mac = (crypto:make-mac :hmac key :sha256)
        for b in bs do (crypto:update-mac mac b)
        finally (return (crypto:produce-mac mac))))


(in-package :hkdf)

(defun extract (salt ikm) (hmac:sha256 salt ikm))
(defun expand (prk info len)
  (loop with tb = (make-array len :fill-pointer 0)
        for i from 1 upto (ceiling (/ len 32))
        for ti = (hmac:sha256 prk (|| info (i2osp i 1)))
          then (hmac:sha256 prk (|| ti info (i2osp i 1)))
        do (loop for j across ti do (vector-push j tb))
        finally (return (coerce tb 'crypto::simple-octet-vector))))

(assert (let* ((prk (extract (i2osp #x000102030405060708090a0b0c 13)
                             (i2osp #x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 22)))
               (okm (expand prk (i2osp #xf0f1f2f3f4f5f6f7f8f9 10) 42)))
          (and (= (os2ip prk) #x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5)
               (= (os2ip okm) #x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865))))


(in-package :kem)

(defparameter *dst-ext* (ascii "ARKG-P256MUL-ECDH"))

(defun ecp2os (P) (subseq (getf (crypto:destructure-public-key P) :y) 1))
(defun os2ecp (b) (crypto:make-public-key
                   :secp256r1
                   :y (concatenate 'crypto::simple-octet-vector #(4) b)))
(defun ecdh (pk sk) (crypto:diffie-hellman sk pk))
(defun mk (prk info)
  (hkdf:expand prk (|| (ascii "ARKG-KEM-HMAC-mac.") *dst-ext* info) 32))
(defun t (prk info)
  (subseq
   (hmac:sha256 (mk prk info) (|| (ascii "ARKG-KEM-HMAC.") *dst-ext* info))
   0 16))
(defun k (prk info)
  (hkdf:expand prk (|| (ascii "ARKG-KEM-HMAC-shared.") *dst-ext* info) 32))

(defun generate-key-pair () (crypto:generate-key-pair :secp256r1))
(defun encaps (pk info)
  (multiple-value-bind (sk-prime pk-prime) (generate-key-pair)
    (let* ((k-prime (ecdh pk sk-prime))
           (c-prime (ecp2os pk-prime))
           (prk (hkdf:extract (i2osp 0 32) k-prime)))
      (values (k prk info) (|| (t prk info) c-prime)))))
(defun decaps (sk c info)
  (let* ((t-in (subseq c 0 16))
         (c-prime (subseq c 16))
         (pk-prime (os2ecp c-prime))
         (k-prime (ecdh pk-prime sk))
         (prk (hkdf:extract (i2osp 0 32) k-prime)))
    (assert (= (os2ip t-in) (os2ip (t prk info))))
    (k prk info)))

(assert (multiple-value-bind (sk pk) (generate-key-pair)
          (multiple-value-bind (k c) (encaps pk (ascii "info"))
            (= (os2ip k) (os2ip (decaps sk c (ascii "info")))))))


;;(defun random-scalar () (+ (crypto:strong-random *n*) 1))
