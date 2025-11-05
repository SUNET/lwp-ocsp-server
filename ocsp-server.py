#!/usr/bin/env python3

import os
import re
from datetime import datetime, timezone

import mariadb
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (OCSPNonce, ReasonFlags, extensions,
                               load_pem_x509_certificate, ocsp)
from flask import Flask, Response, request

app = Flask(__name__)

port = int(os.getenv("PORT", 5000))
sql_user = os.getenv("SQLUSER", "AzureDiamond")
sql_password = os.getenv("SQLPASSWORD", "hunter2")
sql_host = os.getenv("SQLHOST", "127.0.0.1")
sql_port = os.getenv("SQLPORT", 3306)
sql_db = os.getenv("SQLDB", "geteduroam")


config = {
    "host": os.getenv("SQLHOST", "127.0.0.1"),
    "port": os.getenv("SQLPORT", 3306),
    "user": os.getenv("SQLUSER", "AzureDiamond"),
    "password": os.getenv("SQLPASSWORD", "hunter2"),
    "database": os.getenv("SQLDB", "geteduroam"),
}


@app.route("/<unsafe_realm>/", methods=["GET", "POST"])
def ocsp_server(unsafe_realm):

    if re.search('[^a-z-.0-9]',unsafe_realm):
        message = "Bad realm"
        app.logger.error(message)
        return Response(message, status=500)
    else:
        realm = unsafe_realm

    if request.method == "GET":
        return f"Hello from letswifi-portal OCSP service for {realm}!"

    if request.method == "POST":

        conn = mariadb.connect(**config)

        cur = conn.cursor()

        cur.execute(
            "select ca.key, ca.pub from ca inner join realm_signer ON realm_signer.signer_ca_sub=ca.sub where realm_signer.realm = ?",
            (realm,),
        )

        ca_rows = cur.fetchall()

        if len(ca_rows) == 0:
            message = f"Couldn't find {realm} in db"
            app.logger.error(message)
            return Response(message, status=500)
        elif len(ca_rows) != 1:
            message = f"Multiple rows for {realm} found in db"
            app.logger.error(message)
            return Response(message, status=500)

        if ca_rows[0][0]:
            ca_key_bytes = bytes(ca_rows[0][0], "utf-8")
            try:
                ca_key = serialization.load_pem_private_key(ca_key_bytes, None)
            except ValueError:
                message = f"Could not decode key for {realm} found in database"
                app.logger.error(message)
                return Response(message, status=500)
            except:
                message = f"Invalid key for {realm} found in database"
                app.logger.error(message)
                return Response(message, status=500)
        else:
            message = f"No key for {realm} found in database"
            app.logger.error(message)
            return Response(message, status=500)

        if ca_rows[0][1]:
            ca_pem_bytes = bytes(ca_rows[0][1], "utf-8")
            try:
                ca_pem = load_pem_x509_certificate(ca_pem_bytes)
            except:
                message = f"Invalid cert for {realm} found in database"
                app.logger.error(message)
                return Response(message, status=500)
        else:
            message = f"No cert for {realm} found in database"
            app.logger.error(message)
            return Response(message, status=500)

        try:
            ocsp_req = ocsp.load_der_ocsp_request(request.data)
        except ValueError:
            builder = ocsp.OCSPResponseBuilder()
            response = builder.build_unsuccessful(
                ocsp.OCSPResponseStatus.MALFORMED_REQUEST
            )
            response_bytes = response.public_bytes(serialization.Encoding.DER)
            app.logger.error("Malformed request")
            return Response(
                response_bytes, mimetype="application/ocsp-response", status=400
            )

        hash_algorithm = ocsp_req.hash_algorithm
        serial = ocsp_req.serial_number
        try:
            non = ocsp_req.extensions.get_extension_for_class(OCSPNonce)
        except extensions.ExtensionNotFound:
            non = None
            app.logger.debug("No nonce present for this request")

        cur.execute(
            "select x509, revoked, requester, sub from realm_signing_log where realm = ? and serial = ?",
            (
                realm,
                serial,
            ),
        )
        app.logger.info(f"Processing certificate with serial {serial}")

        cert_rows = cur.fetchone()

        conn.close()

        builder = ocsp.OCSPResponseBuilder()
        # Revoked or expired certificates thinned from the database
        if cert_rows is None:
            response = builder.build_unsuccessful(
                ocsp.OCSPResponseStatus.UNAUTHORIZED
            )
            response_bytes = response.public_bytes(serialization.Encoding.DER)
            app.logger.warning(f"Non existing cert (serial {serial}). Removed?")
            return Response(
                response_bytes, mimetype="application/ocsp-response"
            )

        cert = load_pem_x509_certificate(cert_rows[0])
        revoked = cert_rows[1]
        user = cert_rows[2]
        cn = cert_rows[3]
        not_string = " "

        if revoked is None:
            builder = builder.add_response(
                cert=cert,
                issuer=ca_pem,
                algorithm=hash_algorithm,
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=datetime.now(timezone.utc),
                next_update=None,
                revocation_time=None,
                revocation_reason=None,
            )
        else:
            builder = builder.add_response(
                cert=cert,
                issuer=ca_pem,
                algorithm=hash_algorithm,
                cert_status=ocsp.OCSPCertStatus.REVOKED,
                this_update=datetime.now(timezone.utc),
                next_update=None,
                revocation_time=revoked,
                revocation_reason=ReasonFlags.unspecified,
            )
            not_string = " not "

        app.logger.info(f"Certificate for {user} ({cn}) is{not_string}revoked")
        builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, ca_pem)
        if non:
            builder = builder.add_extension(non.value, False)

        # Freeradius seem to require some help in order to validate the response. openssl does not
        builder = builder.certificates([ca_pem])
        response = builder.sign(ca_key, hashes.SHA256())
        response_bytes = response.public_bytes(serialization.Encoding.DER)
        return Response(response_bytes, mimetype="application/ocsp-response")


if __name__ == "__main__":
    app.run(host="::", port=port)
