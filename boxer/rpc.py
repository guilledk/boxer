#!/usr/bin/env python3

import json

from json.decoder import JSONDecodeError


class ServerResponseError(Exception):
    pass


class NodeResponseError(Exception):
    pass


def rpc_request_mod(*args):
    try:
        if isinstance(args[0], bytes):
            obj = json.loads(
                args[0].decode("utf-8")
                )
        else:
            return (False, None)

    except JSONDecodeError:
        return (False, None)

    except UnicodeDecodeError:
        return (False, None)

    return (
        isinstance(obj, dict) and
        "jsonrpc" in obj and
        "method" in obj and
        "params" in obj and
        "id" in obj and
        obj["jsonrpc"] == "2.0",
        obj
        )


def rpc_response_mod(*args):
    try:
        if isinstance(args[0], bytes):
            obj = json.loads(
                args[0].decode("utf-8")
                )
        else:
            return (False, None)

    except JSONDecodeError:
        return (False, None)

    except UnicodeDecodeError:
        return (False, None)

    return (
        isinstance(obj, dict) and
        "jsonrpc" in obj and
        (("result" in obj) ^ ("error" in obj)) and
        "id" in obj and
        obj["id"] == args[1] and
        obj["jsonrpc"] == "2.0",
        obj
        )


class JSONRPCRequest:

    def __init__(self, method, params, id):
        self.method = method
        self.params = params
        self.id = id

    def as_json(self):
        return {
            "jsonrpc": "2.0",
            "method": self.method,
            "params": self.params,
            "id": self.id
        }


class JSONRPCResponseResult:

    def __init__(self, result, id):
        self.result = result
        self.id = id

    def as_json(self):
        return {
            "jsonrpc": "2.0",
            "result": self.result,
            "id": self.id
        }


class JSONRPCResponseError:

    def __init__(self, code, msg, id, data=None):
        self.code = code
        self.msg = msg
        self.id = id
        self.data = data

    def as_json(self):

        err_obj = {
            "code": self.code,
            "message": self.msg
        }

        if self.data is not None:
            err_obj["data"] = self.data

        return {
            "jsonrpc": "2.0",
            "error": err_obj,
            "id": self.id
        }
