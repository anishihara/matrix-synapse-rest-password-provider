# -*- coding: utf-8 -*-
#
# REST endpoint Authentication module for Matrix synapse
# Copyright (C) 2017 Kamax Sarl
#
# https://www.kamax.io/
#
# Modified by Anderson Nishihara to support email as username on login 
# and the new module interface onSynapse v1.46
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from typing import Awaitable, Callable, Optional, Tuple

import synapse
from synapse import module_api

import logging
import requests
import json
import time

logger = logging.getLogger(__name__)


class RestAuthProvider(object):

    def __init__(self, config, api: module_api):
        self.account_handler = api

        if not config.endpoint:
            raise RuntimeError('Missing endpoint config')

        self.endpoint = config.endpoint
        self.regLower = config.regLower
        self.config = config

        logger.info('Endpoint: %s', self.endpoint)
        logger.info('Enforce lowercase username during registration: %s', self.regLower)

        api.register_password_auth_provider_callbacks(
            auth_checkers={
                ("m.login.password", ("password",)): self.check_pass,
            }
        )

        if config.enableEmailAsLogin:
            api.register_password_auth_provider_callbacks(check_3pid_auth=self.check_3pid_auth)

    async def check_3pid_auth(self, medium, address, password):
        logger.info("Got password check for " + address)
        if medium != "email":
            reason = "Medium is not email. Unsuported medium for login using the rest-password-provider. Only username and email is supported."
            logger.warning(reason)
            return None
        auth = await self.check_external_login(username=self.account_handler.get_qualified_user_id(address),password=password)
        if not auth:
            return None
        _,sanitized_user_id = self.sanitize_user_id(address)
        user_id = await self.initialize_user(user_id=sanitized_user_id,auth=auth)
        if not user_id:
            return None
        return user_id,None

    async def check_pass(
        self,
        username: str,
        login_type: str,
        login_dict: "synapse.module_api.JsonDict",
    ):
        if login_type != "m.login.password":
            return None
        matrix_user_id = self.account_handler.get_qualified_user_id(username)
        auth = await self.check_external_login(username=matrix_user_id,password=login_dict.get("password"))
        if not auth:
            return None
        initialized_user_id = await self.initialize_user(user_id=matrix_user_id,auth=auth)
        if not initialized_user_id:
            return None
        return initialized_user_id, None

    def sanitize_user_id(self,localpart):
        # We change '@' to '/' as we cannot user '@' on matrix canonical user id
        sanitized_localpart = localpart.replace("@","/")
        user_id = self.account_handler.get_qualified_user_id(sanitized_localpart)
        return sanitized_localpart,user_id

    def get_external_login_username(self,user_id):
        # As matrix canonical id do not support '@' we change again from '/' to '@' to get the possible email to test for login on external service
        return user_id.replace("/","@")

    async def check_external_login(self, username, password):
        logger.info("Got password check for " + username)
        data = {'user': {'id': username, 'password': password}}
        r = requests.post(self.endpoint + '/_matrix-internal/identity/v1/check_credentials', json=data)
        r.raise_for_status()
        r = r.json()
        if not r["auth"]:
            reason = "Invalid JSON data returned from REST endpoint"
            logger.warning(reason)
            raise RuntimeError(reason)

        auth = r["auth"]
        if not auth["success"]:
            logger.info("User not authenticated")
            return None
        return auth       

    async def initialize_user(self, user_id, auth):
        localpart = user_id.split(":", 1)[0][1:]
        logger.info("User %s authenticated", user_id)

        registration = False
        if not (await self.account_handler.check_user_exists(user_id)):
            logger.info("User %s does not exist yet, creating...", user_id)

            if localpart != localpart.lower() and self.regLower:
                logger.info('User %s was cannot be created due to username lowercase policy', localpart)
                return None

            user_id = await self.account_handler.register_user(localpart=localpart)
            _, access_token, _, _ = await self.account_handler.register_device(user_id)
            registration = True
            logger.info("Registration based on REST data was successful for %s", user_id)
        else:
            logger.info("User %s already exists, registration skipped", user_id)

        if auth["profile"]:
            logger.info("Handling profile data")
            profile = auth["profile"]

            store = self.account_handler._hs.get_profile_handler().store

            if "display_name" in profile and ((registration and self.config.setNameOnRegister) or (self.config.setNameOnLogin)):
                display_name = profile["display_name"]
                logger.info("Setting display name to '%s' based on profile data", display_name)
                await store.set_profile_displayname(localpart, display_name)
            else:
                logger.info("Display name was not set because it was not given or policy restricted it")

            if (self.config.updateThreepid):
                if "three_pids" in profile:
                    logger.info("Handling 3PIDs")

                    external_3pids = []
                    for threepid in profile["three_pids"]:
                        medium = threepid["medium"].lower()
                        address = threepid["address"].lower()
                        external_3pids.append({"medium": medium, "address": address})
                        logger.info("Looking for 3PID %s:%s in user profile", medium, address)

                        validated_at = time_msec()
                        if not (await store.get_user_id_by_threepid(medium, address)):
                            logger.info("3PID is not present, adding")
                            await store.user_add_threepid(
                                user_id,
                                medium,
                                address,
                                validated_at,
                                validated_at
                            )
                        else:
                            logger.info("3PID is present, skipping")

                    if (self.config.replaceThreepid):
                        for threepid in (await store.user_get_threepids(user_id)):
                            medium = threepid["medium"].lower()
                            address = threepid["address"].lower()
                            if {"medium": medium, "address": address} not in external_3pids:
                                logger.info("3PID is not present in external datastore, deleting")
                                await store.user_delete_threepid(
                                    user_id,
                                    medium,
                                    address
                                )

            else:
                logger.info("3PIDs were not updated due to policy")
        else:
            logger.info("No profile data")

        return user_id

    @staticmethod
    def parse_config(config):
        # verify config sanity
        _require_keys(config, ["endpoint"])

        class _RestConfig(object):
            endpoint = ''
            regLower = True
            setNameOnRegister = True
            setNameOnLogin = False
            updateThreepid = True
            replaceThreepid = False
            enableEmailAsLogin = False

        rest_config = _RestConfig()
        rest_config.endpoint = config["endpoint"]

        try:
            rest_config.enableEmailAsLogin = config['policy']['enable_email_as_login']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.regLower = config['policy']['registration']['username']['enforceLowercase']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.setNameOnRegister = config['policy']['registration']['profile']['name']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.setNameOnLogin = config['policy']['login']['profile']['name']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.updateThreepid = config['policy']['all']['threepid']['update']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.replaceThreepid = config['policy']['all']['threepid']['replace']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        return rest_config


def _require_keys(config, required):
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception(
            "REST Auth enabled but missing required config values: {}".format(
                ", ".join(missing)
            )
        )


def time_msec():
    """Get the current timestamp in milliseconds
    """
    return int(time.time() * 1000)
