#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os

from lambda_helper import (get_params,
                           calc_eth_address,
                           get_kms_public_key,
                           sign_kms)

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)


def lambda_handler(event, context):
    _logger.debug("incoming event: {}".format(event))

    try:
        params = get_params()
    except Exception as e:
        raise e

    operation = event.get('operation')
    if not operation:
        raise ValueError('operation needs to be specified in request and needs to be eigher "status" or "send"')

    # {"operation": "status"}
    if operation == 'status':
        key_id = os.getenv('KMS_KEY_ID')
        pub_key = get_kms_public_key(key_id)
        eth_checksum_address = calc_eth_address(pub_key)

        return {'eth_checksum_address': eth_checksum_address}


    # {"operation": "send",
    #  "amount": 123,
    #  "dst_address": "0x...",
    #  "nonce": 0}
    elif operation == 'sign':

        if not (event.get('kyc_id') and event.get('address') and 
                event.get('cause_id', -1) >= 0 and event.get('timeout', -1) >= 0): 
            return {
                'operation': 'sign', 
                'error': 'missing parameter - sign requires kyc_id, address, cause_id and timeout to be specified'
            }

        # get key_id from environment varaible
        key_id = os.getenv('KMS_KEY_ID')

        # get the KYC id 
        kyc_id = event.get('kyc_id')

        # get Address to check approval for
        address = event.get('address')

        # cause id
        cause_id = event.get('cause_id')

        # timeout - in unix time. 
        timeout = event.get('timeout')

        # download public key from KMS
        pub_key = get_kms_public_key(key_id)

        # calculate the Ethereum public address from public key
        eth_checksum_addr = calc_eth_address(pub_key)

        # Create a plaintext message
        plaintext = f"{kyc_id},{address},{cause_id},{timeout}"

        # Sign the message  
        signature = sign_kms(params.get_kms_key_id(), plaintext)    

        # Return the signature & the original message. 
        return {
            "signature": signature,
            "plaintext": plaintext
        }