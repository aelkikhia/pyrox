from pyrox.log import get_logger
import pyrox.filtering as filtering
from pyrox.http import HttpResponse
from pyrox.server.config import load_pyrox_config

from keystoneclient.v2_0.client import Client as KeystoneClient
from keystoneclient.exceptions import Unauthorized


_LOG = get_logger(__name__)
X_AUTH_TOKEN = 'X-Auth-Token'
X_TENANT_NAME = 'X-Tenant-Name'


class KeystoneTokenValidationFilter(filtering.HttpFilter):

    def __init__(self):
        self.reject_response = HttpResponse()
        self.reject_response.status = '401 Unauthorized'
        self.reject_response.header('Content-Length').values.append('0')
        self.config = load_pyrox_config()
        self.admin_client = KeystoneClient(
            token=self.config.keystone.auth_token,
            timeout=self.config.keystone.timeout,
            endpoint=self.config.keystone.endpoint,
            insecure=self.config.keystone.insecure)

    @filtering.handles_request_head
    def on_request_head(self, request_head):
        token_hdr = request_head.get_header(X_AUTH_TOKEN)
        tenant_name_hdr = request_head.get_header(X_TENANT_NAME)

        if (token_hdr and len(token_hdr.values[0]) >= 1) and \
                (tenant_name_hdr and len(tenant_name_hdr.values[0]) >= 1):
            try:
                auth_result = self.admin_client.tokens.authenticate(
                    token=token_hdr.values[0],
                    tenant_name=tenant_name_hdr.values[0])

                if auth_result:
                    request_head.remove_header(X_AUTH_TOKEN)
                    request_head.remove_header(X_TENANT_NAME)
                    tenant_id = auth_result.tenant.get('id', None)
                    return filtering.route(
                        'http://domain.com/?={}'.format(tenant_id))
                    #return filtering.next()

            except Unauthorized:
                filtering.reject(response=self.reject_response)
            except Exception as ex:
                _LOG.exception(ex)

        return filtering.reject(response=self.reject_response)
