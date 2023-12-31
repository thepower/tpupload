local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"
require "resty.openssl.include.evp"
require "resty.openssl.include.objects"
require "resty.openssl.include.x509"
require "resty.openssl.include.stack"

local asn1_macro = require "resty.openssl.include.asn1"

asn1_macro.declare_asn1_functions("X509_CRL", asn1_macro.has_new_ex)

ffi.cdef [[
  X509_NAME *X509_CRL_get_issuer(const X509_CRL *crl);
  int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name);
  int X509_CRL_set_version(X509_CRL *x, long version);

  int X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc);
  X509_EXTENSION *X509_CRL_get_ext(const X509_CRL *x, int loc);
  int X509_CRL_get_ext_by_NID(const X509_CRL *x, int nid, int lastpos);
  // void *X509_CRL_get_ext_d2i(const X509_CRL *x, int nid, int *crit, int *idx);

  int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md);
  int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r);

  int i2d_X509_CRL_bio(BIO *bp, X509_CRL *crl);
  X509_CRL *d2i_X509_CRL_bio(BIO *bp, X509_CRL **crl);
  int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);

  int X509_CRL_print(BIO *bio, X509_CRL *crl);

  int X509_CRL_get0_by_serial(X509_CRL *crl,
                            X509_REVOKED **ret, ASN1_INTEGER *serial);
  // int X509_CRL_get0_by_cert(X509_CRL *crl, X509_REVOKED **ret, X509 *x);

  //STACK_OF(X509_REVOKED)
  OPENSSL_STACK *X509_CRL_get_REVOKED(X509_CRL *crl);

  int X509_CRL_get0_by_serial(X509_CRL *crl,
                             X509_REVOKED **ret, ASN1_INTEGER *serial);

  int X509_CRL_set1_lastUpdate(X509_CRL *x, const ASN1_TIME *tm);
  int X509_CRL_set1_nextUpdate(X509_CRL *x, const ASN1_TIME *tm);
  /*const*/ ASN1_TIME *X509_CRL_get0_lastUpdate(const X509_CRL *crl);
  /*const*/ ASN1_TIME *X509_CRL_get0_nextUpdate(const X509_CRL *crl);
  long X509_CRL_get_version(const X509_CRL *crl);

  X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc);

  int X509_CRL_get_signature_nid(const X509_CRL *crl);
]]
