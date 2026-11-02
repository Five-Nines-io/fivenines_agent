"""A stand-in pymongo client for the mongodb collector's tests (#258).

Only the client is replaced (mongodb._new_client): command in, reply or
exception out, from a contract scenario's `mongo` map. Everything else -- the
collector, pymongo.timeout(), the exception classes -- is real. Replies are
MongoDB Extended JSON (relaxed), decoded the way MongoClient decodes BSON
(naive UTC datetimes), so dates, Timestamps and ObjectIds reach the collector
with their real types.

`mongo` keys:
  hello / isMaster / serverStatus / replSetGetStatus / replSetGetConfig
      the command's reply, or {"raises": <exception spec>}
  oplog
      {"first": <entry>, "last": <entry>} for the two find_one reads, or
      {"raises": <exception spec>}
  monitor
      what the driver's own monitor saw: {"hello": <its unauthenticated
      reply, whose maxWireVersion the server description carries>,
      "error": <exception spec>}

An exception spec is {"type": <pymongo.errors class, or
SSLCertVerificationError>, "reply": <the server's ok:0 reply> (OperationFailure
and its subclasses, NotPrimaryError) | "message": <text> (the others)}.
"""

import json
import ssl
from types import SimpleNamespace

from bson import json_util
from bson.json_util import JSONMode, JSONOptions
from pymongo import errors

JSON_OPTIONS = JSONOptions(json_mode=JSONMode.RELAXED, tz_aware=False)

COMMANDS = ("hello", "isMaster", "serverStatus", "replSetGetStatus", "replSetGetConfig")


class UnexpectedCall(BaseException):
    """The collector sent something the scenario does not list. A
    BaseException, so the collector's own `except Exception` cannot turn it
    into a section error: the test fails instead."""


def ext(value):
    """Extended JSON (already parsed by json) -> the BSON types pymongo
    returns."""
    return json_util.loads(json.dumps(value), json_options=JSON_OPTIONS)


def exception(spec):
    kind = spec["type"]
    if kind == "SSLCertVerificationError":
        return ssl.SSLCertVerificationError(1, spec["message"])
    cls = getattr(errors, kind)
    if kind == "NotPrimaryError":
        reply = ext(spec["reply"])
        return cls(reply["errmsg"], reply)
    if issubclass(cls, errors.OperationFailure):
        reply = ext(spec["reply"])
        return cls(reply.get("errmsg", ""), reply.get("code"), reply)
    return cls(spec["message"])


class _Description:
    def __init__(self, monitor):
        self.error = exception(monitor["error"]) if "error" in monitor else None
        # The driver builds the description from the monitor's hello.
        hello = monitor.get("hello")
        wire = hello.get("maxWireVersion") if isinstance(hello, dict) else None
        self.is_server_type_known = wire is not None
        self.max_wire_version = wire if wire is not None else 0


class _Topology:
    def __init__(self, monitor):
        self._description = _Description(monitor)

    def server_descriptions(self):
        return {("127.0.0.1", 27017): self._description}


class FakeClient:
    """Records every call; answers from the scenario."""

    def __init__(self, mongo, options):
        self.mongo = mongo
        self.options = options
        self.calls = []
        self.closed = False
        monitor = mongo.get("monitor", {})
        self.topology_description = _Topology(monitor)
        if "hello" in monitor:
            event = SimpleNamespace(
                reply=SimpleNamespace(document=ext(monitor["hello"]))
            )
            for listener in options.get("event_listeners", []):
                listener.started(event)
                listener.succeeded(event)
                listener.failed(event)
        self.admin = SimpleNamespace(command=self._command)
        self.local = {"oplog.rs": SimpleNamespace(find_one=self._find_one)}

    def _answer(self, value):
        if isinstance(value, dict) and "raises" in value:
            raise exception(value["raises"])
        return ext(value)

    def _command(self, name):
        self.calls.append(name)
        if name not in COMMANDS or name not in self.mongo:
            raise UnexpectedCall(f"unexpected command {name!r}")
        return self._answer(self.mongo[name])

    def _find_one(self, filter, projection, sort):
        assert filter == {} and projection == {"ts": 1}
        ((field, direction),) = sort
        assert field == "$natural" and direction in (1, -1)
        which = "first" if direction == 1 else "last"
        self.calls.append(f"oplog.{which}")
        if "oplog" not in self.mongo:
            raise UnexpectedCall("unexpected oplog read")
        oplog = self.mongo["oplog"]
        if "raises" in oplog:
            raise exception(oplog["raises"])
        return ext(oplog[which])

    def close(self):
        self.closed = True


def install(monkeypatch, mongo):
    """Replace mongodb._new_client; returns the list the clients land in."""
    from fivenines_agent import mongodb

    clients = []

    def new_client(_pymongo, options):
        client = FakeClient(mongo, options)
        clients.append(client)
        return client

    monkeypatch.setattr(mongodb, "_new_client", new_client)
    return clients
