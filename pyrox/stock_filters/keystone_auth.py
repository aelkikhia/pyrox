from pyrox.log import get_logger
import pyrox.filtering as filtering
from pyrox.http import HttpResponse
from pyrox.server.config import load_pyrox_config

from keystoneclient.v2_0.client import Client as KeystoneClient
from keystoneclient.exceptions import Unauthorized

import redis


_LOG = get_logger(__name__)
X_AUTH_TOKEN = 'X-Auth-Token'
X_TENANT_NAME = 'X-Tenant-Name'


class KeystoneTokenValidationFilter(filtering.HttpFilter):

    def __init__(self):
        self.reject_response = HttpResponse()
        self.reject_response.status = '401 Unauthorized'
        self.reject_response.header('Content-Length').values.append('0')

        self.config = load_pyrox_config()

        self.redis = redis.StrictRedis(host=self.config.redis.host,
                                       port=self.config.redis.port,
                                       db=self.config.redis.db)

        self.admin_client = KeystoneClient(
            token=self.config.keystone.auth_token,
            timeout=self.config.keystone.timeout,
            endpoint=self.config.keystone.endpoint,
            insecure=self.config.keystone.insecure)

    def _cache_set_token(self, token, tenant_id):
        self.redis.set(token, self.config.redis.ttl, tenant_id)

    def _cache_get_tenant_id(self, token):
        return self.redis.get(token)

    def _cached_token_exists(self, token):
        if self.redis.get(token) is not None:
            return True
        return False

    def _prepare_route(self, request, tenant_id):
        request.remove_header(X_AUTH_TOKEN)
        request.remove_header(X_TENANT_NAME)
        return '{0}{1}'.format(
            self.config.route_to, request.url.replace(
                self.config.keystone.url_replacement, tenant_id))

    @filtering.handles_request_head
    def on_request_head(self, request_head):
        try:
            token_hdr = request_head.get_header(X_AUTH_TOKEN)
            tenant_name_hdr = request_head.get_header(X_TENANT_NAME)
            token = token_hdr.values[0]
            tenant_name = tenant_name_hdr.values[0]

            if len(token) >= 1 and len(tenant_name) >= 1:
                # Does the token exist in the cache?
                token_in_cache = self._cached_token_exists(token)
                if not token_in_cache:
                    auth_result = self.admin_client.tokens.authenticate(
                        token=token, tenant_name=tenant_name)

                    if auth_result:
                        tenant_id = auth_result.tenant.get('id', None)
                        self._cache_set_token(token, tenant_id)
                        return filtering.route(self._prepare_route(
                            request_head, tenant_id))

                if token_in_cache:
                    return filtering.route(self._prepare_route(
                        request_head, self._cache_get_tenant_id(token)))

        except Unauthorized:
            filtering.reject(response=self.reject_response)
        except Exception as ex:
            _LOG.exception(ex)

        return filtering.reject(response=self.reject_response)
