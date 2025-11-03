# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
The PID Issuer Web service is a component of the PID Provider backend.
Its main goal is to issue the PID in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.

This config_service.py contains configuration data for the PID Issuer Web service.

NOTE: You should only change it if you understand what you're doing.
"""

import datetime
import logging
from logging.handlers import TimedRotatingFileHandler
import os


class ConfService:
    # ------------------------------------------------------------------------------------------------
    # Frontend service URL
    # service_url = os.getenv("SERVICE_URL", "https://dev.issuer.eudiw.dev/")
    service_url = "https://ec.dev.issuer.eudiw.dev"

    frontend_id = "5d725b3c-6d42-448e-8bfd-1eff1fcf152d"

    wallet_test_url = os.getenv(
        "WALLET_TEST_URL", "https://dev.tester.issuer.eudiw.dev/"
    )

    issuer_url = os.getenv("ISSUER_URL", "https://dev.issuer.eudiw.dev")

    oauth_url = os.getenv("OAUTH_URL", "https://dev.issuer.eudiw.dev/oidc")

    # ------------------------------------------------------------------------------------------------
    # Error list (error number, error string)
    error_list = {
        "-1": "Error undefined. Please contact PID Provider backend support.",
        "0": "No error.",
        "11": "Query with no returnURL.",
        "12": "Query with no version.",
        "13": "Version is not supported.",
        "14": "URL not well formed.",
        "15": "Query with no device_publickey",
        "16": "The device_publickey is not in the correct format",
        "101": "Missing mandatory pid/getpid fields.",
        "102": "Country is not supported.",
        "103": "Certificate not correctly encoded.",
        "104": "Certificate algorithm or curve not supported.",
        "301": "Missing mandatory lightrequest eidasnode fields.",
        "302": "Missing mandatory lightresponse eidasnode fields.",
        "303": "Error obtaining attributes.",
        "304": "PID attribute(s) missing.",
        "305": "Certificate not available.",
        "306": "Date is not in the correct format. Should be YYYY-MM-DD.",
        "401": "Missing mandatory formatter fields.",
        "501": "Missing mandatory IdP fields",
    }

    # ------------------------------------------------------------------------------------------------
    # LOGS

    log_dir = "/tmp/issuer_frontend/log_dev"
    # log_dir = "../../log"
    log_file_info = "logs.log"

    backup_count = 7

    try:
        os.makedirs(log_dir)
    except FileExistsError:
        pass

    log_handler_info = TimedRotatingFileHandler(
        filename=f"{log_dir}/{log_file_info}",
        when="midnight",  # Rotation midnight
        interval=1,  # new file each day
        backupCount=backup_count,
    )

    formatter = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    log_handler_info.setFormatter(formatter)

    app_logger = logging.getLogger("app_logger")
    app_logger.addHandler(log_handler_info)
    app_logger.setLevel(logging.INFO)

    """  logger_error = logging.getLogger("error")
    logger_error.addHandler(log_handler_info)
    logger_error.setLevel(logging.INFO) """

    max_time_data = 5  # maximum minutes allowed for saved information
    schedule_check = 5  # minutes, where every x time the code runs to check the time the data was created
